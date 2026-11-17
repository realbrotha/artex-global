// Command artex runs the ARTEX backend: the dual SQLite graph stores,
// the event-driven exploration engine, and the JSON HTTP API consumed by the
// shadcn/ui frontend.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/selfupdate"
	"github.com/Autumn-27/artex/server"
	"github.com/Autumn-27/artex/wazuh"
)

// version is the build version, injected at release time via
// -ldflags "-X main.version=<tag>". Defaults to "dev" for local builds.
var version = "dev"

const banner = `
    _    ____ _____ _______  __
   / \  |  _ \_   _| ____\ \/ /
  / _ \ | |_) || | |  _|  \  /
 / ___ \|  _ < | | | |___ /  \
/_/   \_\_| \_\|_| |_____/_/\_\
`

// printBanner writes the startup banner + version/runtime info to stdout.
func printBanner(addr string) {
	fmt.Print(banner)
	fmt.Println("  AI autonomous penetration testing system")
	fmt.Printf("  version %s  -  %s/%s  -  %s  -  listening on %s\n\n",
		version, runtime.GOOS, runtime.GOARCH, runtime.Version(), addr)
}

// main only maps run's result onto the process exit code. The exit code is part
// of the update protocol — the supervising start script reads it to decide
// whether to relaunch us (see selfupdate.ExitRestart) — so the body has to live
// in a function that can *return* rather than os.Exit past its own defers.
func main() {
	os.Exit(run())
}

func run() int {
	var (
		addr    = flag.String("addr", "127.0.0.1:8787", "HTTP listen address (default accepts local connections only; use :8787 to serve other hosts)")
		dataDir = flag.String("data", filepath.Join(config.BaseDir(), "data"), "data directory for SQLite stores (default: data/ next to the executable)")
		proxy   = flag.String("proxy", "127.0.0.1:8788", "traffic recording proxy address (empty to disable)")
		// One-shot: register a Wazuh connection from ARTEX_WAZUH_* environment
		// variables and exit. See scripts/wazuh-connect.sh.
		wazuhImport = flag.Bool("wazuh-import", false, "register a Wazuh connection from ARTEX_WAZUH_* environment variables, then exit")
		siemImport  = flag.String("siem-import", "", "import detection inputs (event catalog, criteria, known activity, admin sources, accepted risks) from a Thaki-Siem checkout, then exit")
		risksImport = flag.String("accepted-risks-import", "", "replace the accepted-risk registry with this TSV file (Thaki-Siem registry/accepted-risks.tsv format), then exit")
	)
	flag.Parse()
	if *wazuhImport {
		return importWazuh(*dataDir)
	}
	if *risksImport != "" {
		return importAcceptedRisks(*risksImport)
	}
	if *siemImport != "" {
		return importSiem(*siemImport)
	}

	// hand the build version to the server package so GET /api/health can report it
	// to the frontend top bar.
	server.BuildVersion = version

	printBanner(*addr)

	// capture backend logs into the in-memory sink (still to stderr) so the /logs
	// page can show a live log stream. Do this first, to catch startup logs too.
	server.StartLogCapture()

	// Self-update bootstrap: swap in a staged binary, or count a post-swap boot
	// attempt and roll back if the new build keeps dying. Must run before we open
	// the stores or bind a port — this may end with "exit and let the start script
	// relaunch me", and there is no point paying for either first.
	action, upState := selfupdate.Bootstrap()
	server.SetBootUpdateState(upState)
	if action == selfupdate.Restart {
		return selfupdate.ExitRestart
	}

	// surface which config file the binary reads (absolute, so `go run`'s relative
	// "config.json" — resolved against the CWD — is unambiguous).
	cfgPath := config.Path()
	if abs, e := filepath.Abs(cfgPath); e == nil {
		cfgPath = abs
	}
	if _, e := os.Stat(cfgPath); e == nil {
		log.Printf("[config] config file: %s", cfgPath)
	} else {
		log.Printf("[config] config file: %s (not found - using only environment variable ARTEX_PG_DSN)", cfgPath)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, shutdown := shutdownContext(sigCtx)
	defer shutdown(agent.AbortShutdown)

	mgr, err := server.NewManager(*dataDir, *proxy)
	if err != nil {
		log.Fatalf("open stores: %v", err)
	}
	defer mgr.Close()

	// Surviving this long means a freshly swapped-in build actually works, so drop
	// the upgrade marker and stop counting attempts. Until it fires, every boot
	// increments the count and a build that keeps dying gets rolled back.
	settle := time.AfterFunc(selfupdate.SettleDelay, selfupdate.Settle)
	defer settle.Stop()

	skillDir := config.SkillDir()
	if abs, err := filepath.Abs(skillDir); err == nil {
		skillDir = abs
	}
	log.Printf("[config] skill directory: %s", skillDir)
	srv := server.New(ctx, mgr, skillDir, *dataDir, config.BaseDir())
	srv.WarnIfExposed(*addr)
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("ARTEX %s backend listening on %s (data=%s, workers=%d)", version, *addr, *dataDir, mgr.Workers())
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	// Two ways out: a signal (normal stop → exit 0, the start script stops looping)
	// or a staged update / rollback (→ exit 75, the script relaunches us and the
	// bootstrap above installs the new build).
	code := 0
	select {
	case <-ctx.Done():
	case <-server.RestartRequested():
		code = selfupdate.ExitRestart
		shutdown(agent.AbortShutdown)
	}

	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return code
}

// shutdownContext deliberately does not derive from signalCtx. If it did, the
// parent's plain context.Canceled could win the race before AbortShutdown was
// attached to the child, losing the diagnostic cause in every running Agent.
func shutdownContext(signalCtx context.Context) (context.Context, context.CancelCauseFunc) {
	ctx, shutdown := context.WithCancelCause(context.Background())
	go func() {
		select {
		case <-signalCtx.Done():
			shutdown(agent.AbortShutdown)
		case <-ctx.Done():
		}
	}()
	return ctx, shutdown
}

// importWazuh registers (or updates, matched by name) one Wazuh connection from
// the environment. Values are never logged.
func importWazuh(dataDir string) int {
	env := func(k string) string { return strings.TrimSpace(os.Getenv(k)) }
	name := env("ARTEX_WAZUH_NAME")
	if name == "" {
		name = "wazuh"
	}
	cfg := wazuh.Config{
		ManagerURL:     env("ARTEX_WAZUH_MANAGER_URL"),
		IndexerURL:     env("ARTEX_WAZUH_INDEXER_URL"),
		TLSFingerprint: env("ARTEX_WAZUH_TLS_FINGERPRINT"),
		TLSSkipVerify:  env("ARTEX_WAZUH_TLS_SKIP_VERIFY") == "true",
	}
	creds := wazuh.Credentials{
		ManagerUser:     env("ARTEX_WAZUH_MANAGER_USER"),
		ManagerPassword: os.Getenv("ARTEX_WAZUH_MANAGER_PASSWORD"),
		IndexerUser:     env("ARTEX_WAZUH_INDEXER_USER"),
		IndexerPassword: os.Getenv("ARTEX_WAZUH_INDEXER_PASSWORD"),
	}
	// Open only the database. The full Manager reconciles runtime state
	// (traffic proxy, interrupted jobs) that belongs to the running server.
	dsn, _, err := db.DSN()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wazuh-import: database configuration: %v\n", err)
		return 1
	}
	pg, err := db.Open(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wazuh-import: open database: %v\n", err)
		return 1
	}
	defer pg.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	agents, err := wazuh.Test(ctx, cfg, creds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wazuh-import: connection test failed: %v\n", err)
		return 1
	}
	created, err := server.ImportWazuhSource(ctx, pg, dataDir, config.BaseDir(), name, cfg, creds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wazuh-import: %v\n", err)
		return 1
	}
	verb := "updated"
	if created {
		verb = "created"
	}
	fmt.Printf("wazuh-import: connection %q %s (agents: %d, indexer: %t)\n", name, verb, agents, cfg.IndexerURL != "")
	return 0
}

// importAcceptedRisks replaces the accepted-risk registry from a TSV file. A
// running server applies it at its next sync (within 5 minutes).
func importAcceptedRisks(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "accepted-risks-import: %v\n", err)
		return 1
	}
	risks, err := wazuh.ParseAcceptedRisks(string(raw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "accepted-risks-import: %v\n", err)
		return 1
	}
	dsn, _, err := db.DSN()
	if err != nil {
		fmt.Fprintf(os.Stderr, "accepted-risks-import: database configuration: %v\n", err)
		return 1
	}
	pg, err := db.Open(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "accepted-risks-import: open database: %v\n", err)
		return 1
	}
	defer pg.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = pg.ReplaceAcceptedRisks(ctx, risks); err != nil {
		fmt.Fprintf(os.Stderr, "accepted-risks-import: %v\n", err)
		return 1
	}
	fmt.Printf("accepted-risks-import: %d rows imported\n", len(risks))
	return 0
}

// importSiem loads the detection inputs case extraction needs from a
// Thaki-Siem checkout. Every file is parsed first; nothing is stored unless
// all of them are valid.
func importSiem(dir string) int {
	fail := func(format string, args ...any) int {
		fmt.Fprintf(os.Stderr, "siem-import: "+format+"\n", args...)
		return 1
	}
	read := func(rel string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, rel))
		return string(raw), err
	}
	catalog, err := read("assess/event-catalog.tsv")
	if err != nil {
		return fail("%v", err)
	}
	criteria, err := read("assess/event-criteria.tsv")
	if err != nil {
		return fail("%v", err)
	}
	known, _ := read("registry/known-activity.tsv")           // optional
	admin, _ := read("deploy/lists/siem-admin-src")           // optional
	risksTSV, risksErr := read("registry/accepted-risks.tsv") // optional

	cat, err := wazuh.ParseEventCatalog(catalog)
	if err != nil {
		return fail("%v", err)
	}
	if _, err = wazuh.ParseEventCriteria(criteria); err != nil {
		return fail("%v", err)
	}
	knownRows, err := wazuh.ParseKnownActivity(known)
	if err != nil {
		return fail("%v", err)
	}
	var risks []wazuh.AcceptedRisk
	if risksErr == nil {
		if risks, err = wazuh.ParseAcceptedRisks(risksTSV); err != nil {
			return fail("accepted-risks: %v", err)
		}
	}
	dsn, _, err := db.DSN()
	if err != nil {
		return fail("database configuration: %v", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		return fail("open database: %v", err)
	}
	defer pg.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = pg.SetSiemSettings(ctx, map[string]string{"event-catalog": catalog, "event-criteria": criteria, "known-activity": known, "admin-src": admin}); err != nil {
		return fail("%v", err)
	}
	if risksErr == nil {
		if err = pg.ReplaceAcceptedRisks(ctx, risks); err != nil {
			return fail("%v", err)
		}
	}
	fmt.Printf("siem-import: catalog rules %d (analysed %d), known activity %d, admin prefixes %d, accepted risks %d\n",
		len(cat), len(cat.AnalysedRules()), len(knownRows), len(wazuh.ParseAdminPrefixes(admin)), len(risks))
	return 0
}
