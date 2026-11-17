package wazuh

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// This file and cases.go port the case-candidate extraction of Thaki-Siem
// assess/events.py. Names and constants follow the original so the two can
// be read side by side; wazuh/testdata/gen_golden.py runs the original on the
// test fixture to produce the expected output.

// KST is the timezone events.py reports and buckets days in.
var KST = time.FixedZone("KST", 9*3600)

// Event categories, in the order events.py iterates them.
var eventCats = []string{"EV-AUTH", "EV-ACCESS", "EV-PRIV", "EV-EXEC", "EV-DATA", "EV-RECON", "EV-ERR"}

// AlertSourceFields is the _source projection events.py requests.
var AlertSourceFields = []string{"timestamp", "agent.name", "rule.id", "rule.level", "rule.description", "rule.groups",
	"predecoder.program_name", "syscheck.path", "full_log",
	"data.srcip", "data.dstuser", "data.srcuser", "data.command", "data.url", "data.status",
	"data.haproxy.frontend", "data.audit.auid", "data.audit.exe", "data.audit.execve", "data.audit.file.name",
	"data.auth.display_name", "data.request.remote_address", "data.request.path", "data.request.operation",
	"data.harbor_audit.username", "data.harbor_audit.resource",
	"data.user.username", "data.objectRef", "data.verb", "data.sourceIPs",
	"data.docker.Actor.Attributes.name", "data.docker.Action"}

var unsetAUID = map[string]bool{"4294967295": true, "unset": true, "-1": true, "": true}

// successRules are successful interactive logins (P1 "fail then success", P2).
var successRules = map[string]bool{"5715": true, "100900": true, "100901": true, "100902": true, "100903": true, "100904": true}

// TestHost marks alerts injected by Thaki-Siem rule tests; they must never
// reach the alert index.
const TestHost = "siem-test"

// Alert is one Wazuh alert with the fields the patterns read, normalized once.
type Alert struct {
	T       time.Time
	Host    string
	RuleID  string
	Level   int
	Desc    string
	Groups  []string
	FullLog string
	SrcUser string
	Src     string // src_of
	Actor   string // actor_of
	Object  string // object_of
	K8sUser bool   // actor came from data.user.username
}

func dig(m map[string]any, path string) any {
	var cur any = m
	for _, k := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = obj[k]
	}
	return cur
}

// pyStr mirrors Python str() for the scalar kinds JSON alerts carry.
func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

func gs(m map[string]any, path string) string { return pyStr(dig(m, path)) }

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

var sigRules = []struct {
	re  *regexp.Regexp
	rep string
}{
	{regexp.MustCompile(`AAAA[A-Za-z0-9+/]{36,}={0,2}`), "<KEY>"},
	{regexp.MustCompile(`msg=audit\([\d.:]+\):`), ""},
	{regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b`), "<IP>"},
	{regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`), "<UUID>"},
	{regexp.MustCompile(`(?i)\b[0-9a-f]{12,}\b`), "<HEX>"},
	{regexp.MustCompile(`\b\d+\b`), "<N>"},
}

func signature(text string) string {
	for _, s := range sigRules {
		text = s.re.ReplaceAllString(text, s.rep)
	}
	return clip(text, 160)
}

var execveArg = regexp.MustCompile(`^a(\d+)$`)

func argsOf(m map[string]any) string {
	ex, ok := dig(m, "data.audit.execve").(map[string]any)
	if !ok {
		return ""
	}
	type arg struct {
		n int
		v string
	}
	args := []arg{}
	for k, v := range ex {
		if mm := execveArg.FindStringSubmatch(k); mm != nil {
			n, _ := strconv.Atoi(mm[1])
			args = append(args, arg{n, pyStr(v)})
		}
	}
	sort.Slice(args, func(i, j int) bool { return args[i].n < args[j].n })
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = a.v
	}
	return clip(strings.Join(parts, " "), 200)
}

func srcOf(m map[string]any) string {
	if v := gs(m, "data.srcip"); v != "" {
		return v
	}
	if v := gs(m, "data.request.remote_address"); v != "" {
		return v
	}
	if ips, ok := dig(m, "data.sourceIPs").([]any); ok && len(ips) > 0 {
		if v := pyStr(ips[0]); v != "" {
			return v
		}
	}
	return "-"
}

func actorOf(m map[string]any) (actor string, k8s bool) {
	auid := gs(m, "data.audit.auid")
	if gs(m, "data.audit.exe") != "" || !unsetAUID[auid] {
		if unsetAUID[auid] {
			auid = "-"
		}
		return "auid=" + auid, false
	}
	for _, p := range []string{"data.dstuser", "data.srcuser", "data.auth.display_name", "data.user.username", "data.harbor_audit.username"} {
		if v := gs(m, p); v != "" {
			ku := gs(m, "data.user.username")
			return v, ku != "" && v == ku
		}
	}
	return "-", false
}

func objectOf(m map[string]any) string {
	if ref, ok := dig(m, "data.objectRef").(map[string]any); ok && pyStr(ref["resource"]) != "" {
		ns := "-"
		if v, has := ref["namespace"]; has {
			ns = pyStr(v)
		}
		name := pyStr(ref["name"])
		if name == "" {
			name = pyStr(ref["resource"])
		}
		return fmt.Sprintf("%s %s/%s", gs(m, "data.verb"), ns, name)
	}
	for _, p := range []string{"data.audit.file.name", "syscheck.path", "data.request.path", "data.url", "data.docker.Actor.Attributes.name"} {
		if v := gs(m, p); v != "" {
			if p == "data.url" { // URL ids folded so one API call pattern = one row
				v = signature(strings.SplitN(v, "?", 2)[0])
			}
			return clip(v, 160)
		}
	}
	if exe := gs(m, "data.audit.exe"); exe != "" {
		return clip(strings.TrimSpace(exe+" "+argsOf(m)), 200)
	}
	log := gs(m, "full_log") // state-diff rules carry their change only here
	if log == "" || strings.HasPrefix(log, "{") {
		return ""
	}
	for _, s := range sigRules[:2] { // key blobs, audit record ids; IPs and names kept as evidence
		log = s.re.ReplaceAllString(log, s.rep)
	}
	return clip(strings.Join(strings.Fields(log), " "), 160)
}

func parseAlertTime(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02T15:04:05.000-0700", "2006-01-02T15:04:05-0700", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			// events.py keeps second precision.
			return t.UTC().Truncate(time.Second), nil
		}
	}
	if len(s) >= 19 {
		if t, err := time.Parse("2006-01-02T15:04:05", s[:19]); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("경보 시각을 해석하지 못했습니다: %q", s)
}

// ParseAlert normalizes one alert _source document.
func ParseAlert(src map[string]any) (*Alert, error) {
	t, err := parseAlertTime(gs(src, "timestamp"))
	if err != nil {
		return nil, err
	}
	a := &Alert{T: t, Host: gs(src, "agent.name"), RuleID: gs(src, "rule.id"), Desc: gs(src, "rule.description"),
		FullLog: gs(src, "full_log"), SrcUser: gs(src, "data.srcuser"), Src: srcOf(src), Object: objectOf(src)}
	a.Level, _ = strconv.Atoi(gs(src, "rule.level"))
	if groups, ok := dig(src, "rule.groups").([]any); ok {
		for _, g := range groups {
			a.Groups = append(a.Groups, pyStr(g))
		}
	}
	a.Actor, a.K8sUser = actorOf(src)
	return a, nil
}

func (a *Alert) hasGroup(name string) bool {
	for _, g := range a.Groups {
		if g == name {
			return true
		}
	}
	return false
}

const k8sSA = "system:serviceaccount:"

// actorName builds the subject key: account, K8s certificate or service
// account; the host when there is no subject. K8s subjects are cluster-wide,
// every other account is local to its host.
func actorName(name, host string, k8s bool) string {
	name = strings.TrimSpace(name)
	switch {
	case name == "" || name == "-" || name == "auid=-":
		return "host:" + host
	case strings.HasPrefix(name, k8sSA):
		return "sa:" + strings.Replace(name[len(k8sSA):], ":", "/", 1)
	case k8s:
		if strings.Contains(name, "@") || strings.HasPrefix(name, "oidc:") {
			return "user:" + name
		}
		return "cert:" + name
	}
	return fmt.Sprintf("user:%s@%s", name, host)
}

func actorKey(a *Alert) string { return actorName(a.Actor, a.Host, a.K8sUser) }

// Address ranges Python's ipaddress treats as not global beyond what
// netip.Addr.IsPrivate covers.
var nonGlobal = func() []netip.Prefix {
	out := []netip.Prefix{}
	for _, p := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "64:ff9b:1::/48", "100::/64", "2001::/23"} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

func isGlobal(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range nonGlobal {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// zone classifies a source address: admin (allowed management prefix),
// external (public internet), internal, or "" when it is not an address.
func zone(ip string, admin []string) string {
	if ip == "" || ip == "-" {
		return ""
	}
	for _, p := range admin {
		if strings.HasPrefix(ip, p) {
			return "admin"
		}
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	if isGlobal(addr) {
		return "external"
	}
	return "internal"
}

// offHours: weekends and 20:00-08:00 KST.
func offHours(t time.Time) bool {
	k := t.In(KST)
	wd := k.Weekday()
	return wd == time.Saturday || wd == time.Sunday || k.Hour() >= 20 || k.Hour() < 8
}

func kstStamp(t time.Time) string { return t.In(KST).Format("01-02 15:04") }

// CatalogRow is one rule of event-catalog.tsv.
type CatalogRow struct {
	RuleID   string
	Category string
	Use      string // case | agg | (other: not analysed)
	Attack   string // comma-separated ATT&CK ids
	Title    string
}

// EventCatalog maps rule id to its catalog row.
type EventCatalog map[string]CatalogRow

func tsvRows(text string, skipComments bool) (header []string, rows [][]string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || (skipComments && strings.HasPrefix(line, "#")) {
			continue
		}
		cols := strings.Split(line, "\t")
		if header == nil {
			header = cols
			continue
		}
		rows = append(rows, cols)
	}
	return header, rows
}

func colIndex(header []string, names ...string) (map[string]int, error) {
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.TrimSpace(h)] = i
	}
	for _, n := range names {
		if _, ok := idx[n]; !ok {
			return nil, invalid("열 " + n + " 이(가) 없습니다")
		}
	}
	return idx, nil
}

func cell(row []string, i int) string {
	if i < len(row) {
		return strings.TrimSpace(row[i])
	}
	return ""
}

// ParseEventCatalog reads event-catalog.tsv.
func ParseEventCatalog(tsv string) (EventCatalog, error) {
	header, rows := tsvRows(tsv, false)
	idx, err := colIndex(header, "rule_id", "category", "use", "attack", "title")
	if err != nil {
		return nil, fmt.Errorf("event-catalog: %w", err)
	}
	out := EventCatalog{}
	for _, r := range rows {
		id := cell(r, idx["rule_id"])
		if id == "" {
			continue
		}
		out[id] = CatalogRow{RuleID: id, Category: cell(r, idx["category"]), Use: cell(r, idx["use"]),
			Attack: cell(r, idx["attack"]), Title: cell(r, idx["title"])}
	}
	return out, nil
}

// AnalysedRules are the rule ids whose alerts feed case extraction.
func (c EventCatalog) AnalysedRules() []string {
	out := []string{}
	for id, r := range c {
		if r.Use == "case" || r.Use == "agg" {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// EventCriteria is event-criteria.tsv: detection criterion codes
// (EV-<category>-NN) by correlation pattern and by rule.
type EventCriteria struct {
	Pattern map[string]string // active rows only
	Rule    map[string]string // retired rows included (existing cases keep their code)
	Title   map[string]string
}

// ParseEventCriteria reads event-criteria.tsv.
func ParseEventCriteria(tsv string) (EventCriteria, error) {
	header, rows := tsvRows(tsv, true)
	idx, err := colIndex(header, "code", "title", "pattern", "rules", "status")
	if err != nil {
		return EventCriteria{}, fmt.Errorf("event-criteria: %w", err)
	}
	c := EventCriteria{Pattern: map[string]string{}, Rule: map[string]string{}, Title: map[string]string{}}
	for _, r := range rows {
		code := cell(r, idx["code"])
		if code == "" {
			continue
		}
		c.Title[code] = cell(r, idx["title"])
		if p := cell(r, idx["pattern"]); p != "" && p != "-" && cell(r, idx["status"]) == "active" {
			c.Pattern[p] = code
		}
		for _, rule := range strings.Split(cell(r, idx["rules"]), ",") {
			if rule = strings.TrimSpace(rule); rule != "" && rule != "-" {
				c.Rule[rule] = code
			}
		}
	}
	return c, nil
}

// criterionOf: correlation patterns P1-P8 map to an EV-CORR criterion; a P9
// single-rule case takes the criterion of the rule that produced it.
func (c EventCriteria) criterionOf(pattern string, rules []string) string {
	if code, ok := c.Pattern[pattern]; ok {
		return code
	}
	for _, r := range rules {
		if code, ok := c.Rule[r]; ok {
			return code
		}
	}
	return ""
}

// KnownActivity is one row of registry/known-activity.tsv: approved normal
// operations. A case whose pattern (or criterion) and text match is reported
// as known instead of as a candidate.
type KnownActivity struct {
	Pattern    string `json:"pattern"` // P1..P9, criterion code, or * / empty for any
	Match      string `json:"match"`   // regular expression over entity, actor, hosts and rules
	Reason     string `json:"reason"`
	Expires    string `json:"expires"`
	ApprovedBy string `json:"approved_by"`
	re         *regexp.Regexp
}

// ParseKnownActivity reads registry/known-activity.tsv. Rows whose pattern
// cannot be compiled are rejected: a silently skipped row would turn an
// approved activity back into a candidate without anyone noticing.
func ParseKnownActivity(tsv string) ([]KnownActivity, error) {
	header, rows := tsvRows(tsv, true)
	if header == nil {
		return []KnownActivity{}, nil
	}
	idx, err := colIndex(header, "pattern", "match", "reason", "expires", "approved_by")
	if err != nil {
		return nil, fmt.Errorf("known-activity: %w", err)
	}
	out := []KnownActivity{}
	for n, r := range rows {
		k := KnownActivity{Pattern: cell(r, idx["pattern"]), Match: cell(r, idx["match"]), Reason: cell(r, idx["reason"]),
			Expires: cell(r, idx["expires"]), ApprovedBy: cell(r, idx["approved_by"])}
		if k.Match == "" {
			continue
		}
		if k.re, err = regexp.Compile(k.Match); err != nil {
			return nil, invalid(fmt.Sprintf("known-activity %d번째 행: match 정규식을 해석하지 못했습니다 (%s)", n+1, k.Match))
		}
		if k.re.MatchString("") {
			return nil, invalid(fmt.Sprintf("known-activity %d번째 행: match 가 빈 문자열에도 일치합니다", n+1))
		}
		out = append(out, k)
	}
	return out, nil
}

// activeKnown drops expired rows and compiles patterns of rows that were
// built without ParseKnownActivity (e.g. loaded from storage).
func activeKnown(rows []KnownActivity, today time.Time) []KnownActivity {
	day := today.Format("2006-01-02")
	out := []KnownActivity{}
	for _, k := range rows {
		if k.Match == "" || (k.Expires != "" && k.Expires < day) {
			continue
		}
		if k.re == nil {
			re, err := regexp.Compile(k.Match)
			if err != nil {
				continue
			}
			k.re = re
		}
		out = append(out, k)
	}
	return out
}

// ParseAdminPrefixes reads deploy/lists/siem-admin-src: one "prefix:" per
// line; the text before the first colon is an allowed source prefix.
func ParseAdminPrefixes(text string) []string {
	out := []string{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if p := strings.TrimSpace(strings.SplitN(line, ":", 2)[0]); p != "" {
			out = append(out, p)
		}
	}
	return out
}
