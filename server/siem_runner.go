package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/wazuh"
)

// The runner judges through a local Claude Code CLI instead of the API
// profile: the server runs `claude -p` once per request, with no tools, and
// reads its JSON answer.
var (
	// runnerCommand is the CLI to run; tests point it at a stand-in.
	runnerCommand = "claude"
	runnerModelRe = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]{0,60}$`)
	runnerInfo    struct {
		sync.Mutex
		at      time.Time
		path    string
		version string
	}
)

const runnerProfile = "runner"

// runnerStatus reports whether the CLI is installed, and its version. The
// lookup is cached for a minute.
func runnerStatus() (path, version string) {
	runnerInfo.Lock()
	defer runnerInfo.Unlock()
	if time.Since(runnerInfo.at) < time.Minute {
		return runnerInfo.path, runnerInfo.version
	}
	runnerInfo.at, runnerInfo.path, runnerInfo.version = time.Now(), "", ""
	path, e := exec.LookPath(runnerCommand)
	if e != nil {
		return "", ""
	}
	runnerInfo.path = path
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, e := exec.CommandContext(ctx, path, "--version").Output(); e == nil {
		runnerInfo.version = strings.TrimSpace(string(out))
	}
	return runnerInfo.path, runnerInfo.version
}

// runnerDir is an empty working directory for the CLI, so it picks up no
// project instructions or settings.
func runnerDir() (string, error) {
	dir := filepath.Join(os.TempDir(), "artex-siem-runner")
	return dir, os.MkdirAll(dir, 0o700)
}

type runnerAnswer struct {
	Result  string `json:"result"`
	IsError bool   `json:"is_error"`
	Usage   struct {
		Input       int `json:"input_tokens"`
		Output      int `json:"output_tokens"`
		CacheRead   int `json:"cache_read_input_tokens"`
		CacheCreate int `json:"cache_creation_input_tokens"`
	} `json:"usage"`
}

// errRunner: the CLI could not produce an answer (not installed, not signed
// in, failed). Like a failed API call, it is not a judgment.
var errRunner = errors.New("러너 실행 실패")

// runnerCompleter returns a model caller that runs the local CLI. The case
// data goes in on standard input; the CLI gets no tools, so nothing in the
// data can make it act. model "" uses the CLI's default.
func (s *Server) runnerCompleter(model string) wazuh.Completer {
	return func(ctx context.Context, system, user string, _ int) (string, error) {
		path, _ := runnerStatus()
		if path == "" {
			return "", fmt.Errorf("%w: %s 명령을 찾을 수 없습니다", errRunner, runnerCommand)
		}
		dir, e := runnerDir()
		if e != nil {
			return "", fmt.Errorf("%w: 작업 폴더를 만들지 못했습니다", errRunner)
		}
		args := []string{"-p", "--output-format", "json", "--system-prompt", system, "--tools", "", "--no-session-persistence", "--disable-slash-commands"}
		if model != "" {
			args = append(args, "--model", model)
		}
		started := time.Now()
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Dir = dir
		cmd.Stdin = strings.NewReader(user)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		runErr := cmd.Run()
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		answer := runnerAnswer{}
		parsed := json.Unmarshal(stdout.Bytes(), &answer) == nil
		status := "ok"
		var failure error
		switch {
		case !parsed:
			detail := strings.TrimSpace(stderr.String())
			if detail == "" && runErr != nil {
				detail = runErr.Error()
			}
			failure = fmt.Errorf("%w: %s", errRunner, clipText(detail, 200))
		case answer.IsError:
			failure = fmt.Errorf("%w: %s", errRunner, clipText(answer.Result, 200))
		}
		if failure != nil {
			status = "error"
		}
		// The usage ledger counts runner calls too, under their own profile.
		if s.m.pg != nil {
			label := "claude-cli"
			if model != "" {
				label += ":" + model
			}
			if e := s.m.pg.InsertLLMUsage(&db.LLMUsage{Worker: llmrec.WorkerFrom(ctx), Model: label, ProfileName: runnerProfile,
				LatencyMs: int(time.Since(started).Milliseconds()), InputTokens: answer.Usage.Input + answer.Usage.CacheRead + answer.Usage.CacheCreate,
				OutputTokens: answer.Usage.Output, CacheRead: answer.Usage.CacheRead, CacheWrite: answer.Usage.CacheCreate, Status: status}); e != nil {
				log.Printf("[siem-runner] usage: %v", e)
			}
		}
		if failure != nil {
			return "", failure
		}
		return answer.Result, nil
	}
}

func clipText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// judgeBackend returns the model caller the schedule settings select, the
// model name to record, and a message when judging cannot run. A runner
// that is not installed falls back to the API profile when there is one.
func (s *Server) judgeBackend(sched wazuh.Schedule) (wazuh.Completer, string, string) {
	s.cfgMu.Lock()
	provider, apiModel, apiReady := s.llmProv, s.llmCfg.Model, s.llmOn && s.llmProv != nil
	s.cfgMu.Unlock()
	if sched.JudgeMode == wazuh.JudgeRunner {
		if path, _ := runnerStatus(); path != "" {
			model := "claude-cli"
			if sched.RunnerModel != "" {
				model += ":" + sched.RunnerModel
			}
			return s.runnerCompleter(sched.RunnerModel), model, ""
		}
		if !apiReady {
			return nil, "", "러너(" + runnerCommand + ")를 찾을 수 없고 LLM 프로필도 없습니다"
		}
		log.Printf("[siem-runner] %s not found: using the API profile", runnerCommand)
	}
	if !apiReady {
		return nil, "", "LLM 이 설정되지 않았습니다. LLM 메뉴에서 모델을 연결해 주세요"
	}
	return caseCompleter(provider), apiModel, ""
}

// testRunner runs one tiny request through the CLI, so the settings page can
// say whether the runner works before it is selected.
func (s *Server) testRunner(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Model string `json:"model"`
	}
	if !decodePurpleRequestLimit(w, r, &in, 1<<10) {
		return
	}
	if !runnerModelRe.MatchString(in.Model) {
		writeErr(w, 400, "모델 이름을 확인해 주세요")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 25*time.Second)
	defer cancel()
	started := time.Now()
	text, e := s.runnerCompleter(in.Model)(llmrec.WithWorker(ctx, "siem-runner-test"),
		"Reply with the single word OK and nothing else.", "ping", 16)
	out := map[string]any{"ok": e == nil, "ms": time.Since(started).Milliseconds()}
	if e != nil {
		out["error"] = e.Error()
	} else {
		out["answer"] = clipText(strings.TrimSpace(text), 80)
	}
	writeJSON(w, 200, out)
}
