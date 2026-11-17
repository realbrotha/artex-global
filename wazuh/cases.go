package wazuh

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Correlation thresholds (events.py; Thaki-Siem deploy/rules/thresholds.tsv).
const (
	nearGap     = 15 * time.Minute // cases with events this close are listed as related
	p1Fails     = 5
	p1Gap       = 30 * time.Minute
	p6Sources   = 10
	p7Requests  = 20
	followGap   = time.Hour // activity after a login attributed to that session
	clusterGap  = time.Hour // P9: same criterion/actor events closer than this form one burst
	timelineMax = 50
	chainGap    = 24 * time.Hour // P3: login -> privilege change -> intrusion activity
	chainStep   = 2 * time.Hour  // P3: intrusion activity must follow a privilege change this closely
	p4After     = time.Hour
	p5After     = time.Hour
	p8Ratio     = 5  // P8: day count >= 5x median of previous days ...
	p8Min       = 10 // ... and >= 10
)

var exfilRules = map[string]bool{"100815": true, "100816": true, "100817": true, "100818": true, "100819": true, "101008": true}

// ATT&CK v19 replaced the T1562 family with T1685 (tools, logs) and T1686
// (firewall); T1070.002 became T1685.006 and stays "trace removal".
var (
	tracePrefix   = []string{"T1070", "T1685.006"}
	defensePrefix = []string{"T1562", "T1685", "T1686"}
)

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func isDefense(attack string) bool {
	return hasAnyPrefix(attack, defensePrefix) && !hasAnyPrefix(attack, tracePrefix)
}

// posture link: pattern -> KISA controls whose failed state on the same host
// makes the case more likely.
var posturePattern = map[string][]string{"P1": {"U-03", "U-01"}, "P2": {"U-28", "U-01"}, "P6": {"U-03"},
	"P3": {"U-63", "U-28"}, "P4": {"U-66"}, "P5": {"U-18"}}

var crashRe = regexp.MustCompile(`(sshd|sudo)\[?\d*\]?:? .*segfault|segfault.*\b(sshd|sudo)\b`)

// Severities, most severe first.
var severities = []string{"Critical", "High", "Medium", "Low", "Info"}

func sevIndex(s string) int {
	for i, v := range severities {
		if v == s {
			return i
		}
	}
	return len(severities)
}

// sevUp raises a severity n steps, never above cap.
func sevUp(sev string, n int, cap string) string {
	if sevIndex(sev) > sevIndex(cap) {
		i := sevIndex(sev) - n
		if i < sevIndex(cap) {
			i = sevIndex(cap)
		}
		return severities[i]
	}
	return sev
}

// CaseEvent is one timeline row of a case.
type CaseEvent struct {
	T      time.Time `json:"t"`
	Host   string    `json:"host"`
	Rule   string    `json:"rule"`
	Level  int       `json:"level"`
	Actor  string    `json:"actor"`
	Src    string    `json:"src"`
	Object string    `json:"object"`
	Desc   string    `json:"desc"`
}

// Case is one case candidate: one detection criterion on one subject.
type Case struct {
	ID        string      `json:"id"`
	Pattern   string      `json:"pattern"` // P1..P9
	Score     int         `json:"score"`   // 0 when matched by known activity
	Entity    string      `json:"entity"`
	Hosts     []string    `json:"hosts"`
	First     time.Time   `json:"first"`
	Last      time.Time   `json:"last"`
	N         int         `json:"n"`
	Attack    []string    `json:"attack"`
	Summary   string      `json:"summary"`
	Known     string      `json:"known,omitempty"` // registry reason when it is approved activity
	Near      []string    `json:"near"`
	Severity  string      `json:"severity"`
	SevBasis  string      `json:"sev_basis"`
	Criterion string      `json:"criterion"`
	Title     string      `json:"title,omitempty"` // criterion title
	Actor     string      `json:"actor"`
	Timeline  []CaseEvent `json:"timeline"`
}

// CaseInput is everything case extraction reads.
type CaseInput struct {
	Alerts   []*Alert // timestamp order, as fetched
	Catalog  EventCatalog
	Criteria EventCriteria
	Known    []KnownActivity
	Admin    []string // allowed management source prefixes
	// Seen holds (host, user, src) first observed inside the window; nil
	// when the first-seen baseline is unavailable (no "new source" signal).
	Seen map[[3]string]bool
	// Posture holds failed KISA codes per host.
	Posture map[string]map[string]bool
	Today   time.Time // known-activity expiry
}

type ev struct {
	t time.Time
	a *Alert
}

type catEv struct {
	ev
	c CatalogRow
}

type signals struct {
	why    []string
	priv   bool
	attack bool
	actor  string
}

type rawCase struct {
	pattern string
	score   int
	entity  string
	evs     []ev
	summary string
	sig     signals
	hit     *KnownActivity
}

func byTime(evs []ev) []ev {
	out := append([]ev(nil), evs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].t.Before(out[j].t) })
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// byActor splits events by subject key, in order of first appearance.
func byActor(evs []ev, key func(*Alert) string) (order []string, parts map[string][]ev) {
	parts = map[string][]ev{}
	for _, e := range evs {
		k := key(e.a)
		if _, ok := parts[k]; !ok {
			order = append(order, k)
		}
		parts[k] = append(parts[k], e)
	}
	return order, parts
}

// caseSeverity is the fixed severity table. Signals: source (public
// internet, outside the allowed management range), privilege use after
// login, highest rule level, off hours.
func caseSeverity(pattern string, sig signals, evs []ev, admin []string, known bool) (string, string) {
	if known {
		return "Info", "정상 업무 등록부 일치"
	}
	ext, off, lv := false, false, 0
	for _, e := range evs {
		if e.a.Src != "-" && e.a.Src != "" && zone(e.a.Src, admin) == "external" {
			ext = true
		}
		if offHours(e.t) {
			off = true
		}
		if e.a.Level > lv {
			lv = e.a.Level
		}
	}
	basis := []string{}
	var sev string
	switch pattern {
	case "P1", "P3", "P4", "P5":
		sev = "High"
		basis = append(basis, map[string]string{"P1": "실패 후 성공", "P3": "침해 연쇄", "P4": "방어 무력화", "P5": "민감정보 반출"}[pattern])
		if ext {
			sev = "Critical"
			basis = append(basis, "외부 출발지")
		}
	case "P2":
		switch {
		case contains(sig.why, "허용 대역 외"):
			sev = "Medium"
			if sig.priv || ext {
				sev = "High"
			}
			if sig.priv {
				basis = append(basis, "허용 대역 밖 로그인 + 권한 사용")
			} else {
				basis = append(basis, "허용 대역 밖 로그인")
			}
			if ext && sig.priv {
				sev = "Critical"
				basis = append(basis, "외부 출발지")
			}
		case contains(sig.why, "root 직접"):
			sev = "Medium"
			basis = append(basis, "root 직접 로그인")
		default:
			sev = "Low"
			if sig.priv {
				sev = "Medium"
				basis = append(basis, "최초 출발지 로그인 + 권한 사용")
			} else {
				basis = append(basis, "최초 출발지 로그인")
			}
		}
		if off && (sev == "Medium" || sev == "Low") && sig.priv {
			sev = sevUp(sev, 1, "High")
			basis = append(basis, "업무 외 시간")
		}
	case "P6":
		sev = "Medium"
		basis = append(basis, "분산 대입")
	case "P7":
		sev = "Low"
		if sig.attack {
			sev = "Medium"
			basis = append(basis, "외부 탐색 + 공격 패턴")
		} else {
			basis = append(basis, "외부 탐색")
		}
	case "P8":
		sev = "Low"
		basis = append(basis, "오류 급증")
	default: // P9 single high-level rule
		switch {
		case lv >= 14:
			sev = "High"
		case lv >= 12:
			sev = "Medium"
		default:
			sev = "Low"
		}
		basis = append(basis, fmt.Sprintf("rule level %d", lv))
		if off && sev == "Medium" {
			sev = "High"
			basis = append(basis, "업무 외 시간")
		}
		if ext && sevIndex(sev) > sevIndex("High") {
			sev = sevUp(sev, 1, "High")
			basis = append(basis, "외부 출발지")
		}
	}
	return sev, strings.Join(basis, " · ")
}

func plural(n int, format string) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(format, n)
}

// BuildCases extracts case candidates from alerts: correlation patterns
// P1-P8, then remaining high-level single rules (P9), merged so that one
// case is one detection criterion on one subject.
func BuildCases(in CaseInput) []Case {
	cat, admin := in.Catalog, in.Admin
	by := map[string][]catEv{}
	for _, a := range in.Alerts {
		c, ok := cat[a.RuleID]
		if !ok {
			continue
		}
		for _, name := range eventCats {
			if c.Category == name {
				by[name] = append(by[name], catEv{ev{a.T, a}, c})
			}
		}
	}
	attackOf := func(a *Alert) string { return cat[a.RuleID].Attack }
	out := []rawCase{}

	var logins, sudos []ev
	for _, x := range by["EV-ACCESS"] {
		if successRules[x.a.RuleID] {
			logins = append(logins, x.ev)
		}
		if x.a.hasGroup("sudo") {
			sudos = append(sudos, x.ev)
		}
	}
	used := map[*Alert]bool{} // alerts consumed by correlation patterns (kept out of P2 and P9)
	use := func(evs []ev) {
		for _, e := range evs {
			used[e.a] = true
		}
	}
	session := func(host, user string, t0 time.Time) []ev {
		var s []ev
		for _, e := range sudos {
			if e.a.Host == host && e.a.SrcUser == user && !e.t.Before(t0) && !e.t.After(t0.Add(followGap)) {
				s = append(s, e)
			}
		}
		return s
	}
	caseEvents := func(name string) []ev {
		var s []ev
		for _, x := range by[name] {
			if x.c.Use == "case" {
				s = append(s, x.ev)
			}
		}
		return s
	}

	// P1 fail burst then success, same src/user
	type srcUser struct{ src, user string }
	failOrder, fails := []srcUser{}, map[srcUser][]ev{}
	for _, x := range by["EV-AUTH"] {
		k := srcUser{x.a.Src, x.a.Actor}
		if _, ok := fails[k]; !ok {
			failOrder = append(failOrder, k)
		}
		fails[k] = append(fails[k], x.ev)
	}
	loginsByTime := byTime(logins)
	for _, k := range failOrder {
		fl := byTime(fails[k])
		for _, l := range loginsByTime {
			if l.a.Src != k.src || l.a.Actor != k.user {
				continue
			}
			var before []ev
			for _, f := range fl {
				if !f.t.Before(l.t.Add(-p1Gap)) && !f.t.After(l.t) {
					before = append(before, f)
				}
			}
			if len(before) < p1Fails {
				continue
			}
			fol := session(l.a.Host, k.user, l.t)
			evs := append(append(append([]ev{}, before...), l), fol...)
			use(evs)
			score := 80
			if len(fol) > 0 {
				score += 10
			}
			out = append(out, rawCase{pattern: "P1", score: score, entity: fmt.Sprintf("src=%s user=%s", k.src, k.user), evs: evs,
				summary: fmt.Sprintf("실패 %d회 후 로그인 성공%s", len(before), plural(len(fol), ", sudo %d회")),
				sig:     signals{priv: len(fol) > 0, actor: actorKey(l.a)}})
			break
		}
	}

	priv, execs := caseEvents("EV-PRIV"), caseEvents("EV-EXEC")

	// P3 intrusion chain: login -> host privilege change -> intrusion activity
	// on the same host within 24h. Host-level only (no remote source): changes
	// made over the network through an API are excluded. State-diff rules
	// carry no actor, so each change is attributed to the latest preceding
	// login on that host.
	var hPriv, hExec []ev
	for _, e := range priv {
		if e.a.Src == "-" {
			hPriv = append(hPriv, e)
		}
	}
	for _, e := range execs {
		if e.a.Src == "-" {
			hExec = append(hExec, e)
		}
	}
	type chain struct {
		login ev
		priv  []ev
	}
	chainOrder, chains := []*Alert{}, map[*Alert]*chain{}
	for _, p := range byTime(hPriv) {
		var latest *ev
		for i := range logins {
			l := &logins[i]
			if l.a.Host == p.a.Host && !l.t.Before(p.t.Add(-chainGap)) && !l.t.After(p.t) && (latest == nil || l.t.After(latest.t)) {
				latest = l
			}
		}
		if latest == nil {
			continue
		}
		if _, ok := chains[latest.a]; !ok {
			chainOrder = append(chainOrder, latest.a)
			chains[latest.a] = &chain{login: *latest}
		}
		chains[latest.a].priv = append(chains[latest.a].priv, p)
	}
	taken := map[*Alert]bool{}
	for _, key := range chainOrder {
		c := chains[key]
		h, u, lt := c.login.a.Host, c.login.a.Actor, c.login.t
		var xEv []ev
		for _, e := range hExec {
			if e.a.Host != h || e.t.After(lt.Add(chainGap)) || taken[e.a] {
				continue
			}
			for _, p := range c.priv {
				if !e.t.Before(p.t) && !e.t.After(p.t.Add(chainStep)) {
					xEv = append(xEv, e)
					break
				}
			}
		}
		if len(xEv) == 0 {
			continue
		}
		for _, e := range xEv {
			taken[e.a] = true
		}
		fol := session(h, u, lt)
		evs := append(append(append([]ev{c.login}, c.priv...), xEv...), fol...)
		use(evs)
		out = append(out, rawCase{pattern: "P3", score: 90, entity: fmt.Sprintf("host=%s user=%s src=%s", h, u, c.login.a.Src), evs: evs,
			summary: fmt.Sprintf("로그인 → 호스트 권한·계정 변경 %d건 → 2시간 내 침해 행위 %d건 (직전 로그인 기준)", len(c.priv), len(xEv)),
			sig:     signals{actor: actorKey(c.login.a)}})
	}

	// P4 defence evasion followed by data access or trace removal
	var defense []ev
	for _, e := range execs {
		if isDefense(attackOf(e.a)) {
			defense = append(defense, e)
		}
	}
	dataCase := caseEvents("EV-DATA")
	isDataCase := map[*Alert]bool{}
	for _, e := range dataCase {
		isDataCase[e.a] = true
	}
	p4Pool := append(append([]ev{}, dataCase...), execs...)
	for _, d := range byTime(defense) {
		if used[d.a] {
			continue
		}
		h, end := d.a.Host, d.t.Add(p4After)
		var after []ev
		trace := 0
		for _, e := range p4Pool {
			if e.a.Host != h || e.t.Before(d.t) || e.t.After(end) || e.a == d.a {
				continue
			}
			isTrace := hasAnyPrefix(attackOf(e.a), tracePrefix)
			if isDataCase[e.a] || isTrace {
				after = append(after, e)
				if isTrace {
					trace++
				}
			}
		}
		if len(after) == 0 {
			continue
		}
		var burst []ev // e.g. a rule flush raises one alert per rule
		for _, e := range defense {
			if e.a.Host == h && !e.t.Before(d.t) && !e.t.After(end) {
				burst = append(burst, e)
			}
		}
		evs := append(append([]ev{}, burst...), after...)
		use(evs)
		out = append(out, rawCase{pattern: "P4", score: 90, entity: fmt.Sprintf("host=%s rule=%s", h, d.a.RuleID), evs: evs,
			summary: fmt.Sprintf("%s %d건 후 1시간 내 민감정보 접근·흔적 삭제 %d건%s", clip(d.a.Desc, 40), len(burst), len(after), plural(trace, " (흔적 삭제 %d)")),
			sig:     signals{actor: "host:" + h}})
	}

	// P5 credential/secret read followed by dump, archive or transfer on the same host
	var reads, exfil []ev
	for _, x := range by["EV-DATA"] {
		if x.c.Use == "case" && !exfilRules[x.a.RuleID] {
			reads = append(reads, x.ev)
		}
	}
	for _, name := range []string{"EV-DATA", "EV-EXEC"} {
		for _, x := range by[name] {
			if exfilRules[x.a.RuleID] {
				exfil = append(exfil, x.ev)
			}
		}
	}
	readHosts := map[string]bool{}
	for _, e := range reads {
		readHosts[e.a.Host] = true
	}
	for _, h := range sortedSet(readHosts) {
		var rEv, xEv []ev
		for _, e := range reads {
			if e.a.Host == h {
				rEv = append(rEv, e)
			}
		}
		rEv = byTime(rEv)
		for _, e := range exfil {
			if e.a.Host != h {
				continue
			}
			for _, r := range rEv {
				if !e.t.Before(r.t) && !e.t.After(r.t.Add(p5After)) {
					xEv = append(xEv, e)
					break
				}
			}
		}
		if len(xEv) == 0 {
			continue
		}
		evs := append(append([]ev{}, rEv...), xEv...)
		use(evs)
		out = append(out, rawCase{pattern: "P5", score: 85, entity: "host=" + h, evs: evs,
			summary: fmt.Sprintf("민감정보 접근 %d건 → 1시간 내 반출 도구 %d건", len(rEv), len(xEv)), sig: signals{actor: "host:" + h}})
	}

	// P8 error burst: last day >= 5x median of previous days, or sshd/sudo crash
	type hostRule struct{ host, rule string }
	perOrder, per := []hostRule{}, map[hostRule]map[string][]ev{}
	for _, x := range by["EV-ERR"] {
		k := hostRule{x.a.Host, x.a.RuleID}
		if _, ok := per[k]; !ok {
			perOrder = append(perOrder, k)
			per[k] = map[string][]ev{}
		}
		day := x.t.In(KST).Format("2006-01-02")
		per[k][day] = append(per[k][day], x.ev)
	}
	for _, k := range perOrder {
		days := per[k]
		order := make([]string, 0, len(days))
		for d := range days {
			order = append(order, d)
		}
		sort.Strings(order)
		last := days[order[len(order)-1]]
		prev := []int{}
		for _, d := range order[:len(order)-1] {
			prev = append(prev, len(days[d]))
		}
		sort.Ints(prev)
		med := 0
		if len(prev) > 0 {
			med = prev[len(prev)/2]
		}
		floor := med
		if floor < 1 {
			floor = 1
		}
		if len(last) >= p8Min && len(last) >= p8Ratio*floor {
			out = append(out, rawCase{pattern: "P8", score: 30, entity: fmt.Sprintf("host=%s rule=%s", k.host, k.rule), evs: last,
				summary: fmt.Sprintf("%s %s 하루 %d건 (이전 중앙값 %d)", last[0].t.In(KST).Format("01-02"), clip(last[0].a.Desc, 40), len(last), med),
				sig:     signals{actor: "host:" + k.host}})
		}
	}
	var crash []ev
	crashHosts := map[string]bool{}
	for _, name := range eventCats {
		for _, x := range by[name] {
			if crashRe.MatchString(x.a.FullLog) {
				crash = append(crash, x.ev)
				crashHosts[x.a.Host] = true
			}
		}
	}
	for _, h := range sortedSet(crashHosts) {
		var evs []ev
		for _, e := range crash {
			if e.a.Host == h {
				evs = append(evs, e)
			}
		}
		out = append(out, rawCase{pattern: "P8", score: 50, entity: fmt.Sprintf("host=%s crash=sshd·sudo", h), evs: evs,
			summary: fmt.Sprintf("sshd·sudo 비정상 종료(segfault) %d건", len(evs)), sig: signals{actor: "host:" + h}})
	}

	// P2 success from out-of-range / new source / direct root
	for _, l := range logins {
		if used[l.a] {
			continue
		}
		s, u, h := l.a.Src, l.a.Actor, l.a.Host
		why := []string{}
		if zone(s, admin) == "external" || l.a.RuleID == "100900" {
			why = append(why, "허용 대역 외")
		}
		if in.Seen != nil && in.Seen[[3]string{h, u, s}] {
			why = append(why, "최초 출발지")
		}
		if u == "root" || l.a.RuleID == "100904" {
			why = append(why, "root 직접")
		}
		if len(why) == 0 {
			continue
		}
		fol := session(h, u, l.t)
		evs := append([]ev{l}, fol...)
		score := 50 + 10*len(why)
		if len(fol) > 0 {
			score += 10
		}
		out = append(out, rawCase{pattern: "P2", score: score, entity: fmt.Sprintf("user=%s src=%s host=%s", u, s, h), evs: evs,
			summary: fmt.Sprintf("로그인 성공: %s%s", strings.Join(why, "·"), plural(len(fol), ", sudo %d회")),
			sig:     signals{why: why, priv: len(fol) > 0 || contains(why, "root 직접"), actor: actorKey(l.a)}})
		use(evs)
	}

	// P6 one account, many failing sources. Judged across all hosts; one
	// case per subject (account on a host).
	userOrder, perUser := []string{}, map[string][]ev{}
	for _, x := range by["EV-AUTH"] {
		if x.a.Actor == "-" {
			continue
		}
		if _, ok := perUser[x.a.Actor]; !ok {
			userOrder = append(userOrder, x.a.Actor)
		}
		perUser[x.a.Actor] = append(perUser[x.a.Actor], x.ev)
	}
	distinctSrc := func(evs []ev) int {
		s := map[string]bool{}
		for _, e := range evs {
			s[e.a.Src] = true
		}
		return len(s)
	}
	for _, u := range userOrder {
		fl := perUser[u]
		total := distinctSrc(fl)
		if total < p6Sources {
			continue
		}
		order, parts := byActor(fl, actorKey)
		for _, act := range order {
			part := parts[act]
			extra := ""
			if len(part) < len(fl) {
				extra = fmt.Sprintf(" (전체 출발지 %d곳)", total)
			}
			out = append(out, rawCase{pattern: "P6", score: 60, entity: "user=" + u, evs: part,
				summary: fmt.Sprintf("출발지 %d곳에서 인증 실패 %d회%s", distinctSrc(part), len(part), extra), sig: signals{actor: act}})
		}
	}

	// P7 external reconnaissance / web attack. Subject = the probed host.
	srcOrder, perSrc := []string{}, map[string][]catEv{}
	for _, x := range by["EV-RECON"] {
		if _, ok := perSrc[x.a.Src]; !ok {
			srcOrder = append(srcOrder, x.a.Src)
		}
		perSrc[x.a.Src] = append(perSrc[x.a.Src], x)
	}
	for _, s := range srcOrder {
		rl := perSrc[s]
		isAttack := map[*Alert]bool{}
		var all []ev
		for _, x := range rl {
			if x.c.Use == "case" {
				isAttack[x.a] = true
			}
			all = append(all, x.ev)
		}
		if zone(s, admin) != "external" || (len(rl) < p7Requests && len(isAttack) == 0) {
			continue
		}
		order, parts := byActor(byTime(all), func(a *Alert) string { return "host:" + a.Host })
		for _, act := range order {
			part := parts[act]
			atk := 0
			for _, e := range part {
				if isAttack[e.a] {
					atk++
				}
			}
			score := 40
			if atk > 0 {
				score += 10
			}
			out = append(out, rawCase{pattern: "P7", score: score, entity: "src=" + s, evs: part,
				summary: fmt.Sprintf("외부 탐색 %d건%s", len(part), plural(atk, ", 공격 패턴 rule %d건")), sig: signals{attack: atk > 0, actor: act}})
		}
	}

	// P9 remaining high-level case rules: one case per criterion and subject;
	// separate bursts are reported as occurrences (periodic jobs stay one row).
	type critActor struct{ crit, actor string }
	singleOrder, single := []critActor{}, map[critActor][]ev{}
	for _, name := range eventCats {
		if name == "EV-AUTH" || name == "EV-RECON" {
			continue
		}
		for _, x := range by[name] {
			if x.c.Use != "case" || x.a.Level < 10 || used[x.a] {
				continue
			}
			crit, ok := in.Criteria.Rule[x.a.RuleID]
			if !ok {
				crit = "rule=" + x.a.RuleID
			}
			k := critActor{crit, actorKey(x.a)}
			if _, seen := single[k]; !seen {
				singleOrder = append(singleOrder, k)
			}
			single[k] = append(single[k], x.ev)
		}
	}
	for _, k := range singleOrder {
		el := byTime(single[k])
		var starts []time.Time
		lv := 0
		objs, ruleCount, ruleOrder := map[string]bool{}, map[string]int{}, []string{}
		for i, e := range el {
			if i == 0 || e.t.Sub(el[i-1].t) > clusterGap {
				starts = append(starts, e.t)
			}
			if e.a.Level > lv {
				lv = e.a.Level
			}
			if e.a.Object != "" {
				objs[e.a.Object] = true
			}
			if ruleCount[e.a.RuleID] == 0 {
				ruleOrder = append(ruleOrder, e.a.RuleID)
			}
			ruleCount[e.a.RuleID]++
		}
		top := ruleOrder[0] // most frequent rule; first seen wins a tie
		for _, r := range ruleOrder {
			if ruleCount[r] > ruleCount[top] {
				top = r
			}
		}
		desc := ""
		for _, e := range el {
			if e.a.RuleID == top {
				desc = clip(e.a.Desc, 70)
				break
			}
		}
		byNumber := append([]string(nil), ruleOrder...)
		sort.Slice(byNumber, func(i, j int) bool {
			a, _ := strconv.Atoi(byNumber[i])
			b, _ := strconv.Atoi(byNumber[j])
			return a < b
		})
		summary := desc
		if len(ruleCount) > 1 {
			summary += fmt.Sprintf(" / rule %d종", len(ruleCount))
		}
		if len(objs) > 1 {
			summary += fmt.Sprintf(" / 대상 %d종", len(objs))
		}
		if len(starts) > 1 {
			shown := starts
			if len(shown) > 6 {
				shown = shown[:6]
			}
			stamps := make([]string, len(shown))
			for i, t := range shown {
				stamps[i] = kstStamp(t)
			}
			summary += fmt.Sprintf(" / 발생 구간 %d회 (%s)", len(starts), strings.Join(stamps, ", "))
		}
		score := 35
		if lv >= 12 {
			score = 50
		}
		out = append(out, rawCase{pattern: "P9", score: score,
			entity: fmt.Sprintf("rule=%s actor=%s", strings.Join(byNumber, ","), el[0].a.Actor), evs: el, summary: summary, sig: signals{actor: k.actor}})
	}

	return mergeCases(out, in)
}

func evHostsRules(evs []ev) (hosts, rules []string) {
	h, r := map[string]bool{}, map[string]bool{}
	for _, e := range evs {
		h[e.a.Host] = true
		r[e.a.RuleID] = true
	}
	return sortedSet(h), sortedSet(r)
}

// mergeCases folds raw pattern hits so one case is one criterion on one
// subject. The known-activity registry is applied per hit before merging:
// when only some hits match, they are dropped and the rest form the case.
func mergeCases(raw []rawCase, in CaseInput) []Case {
	known := activeKnown(in.Known, in.Today)
	type key struct{ crit, actor string }
	order, parts := []key{}, map[key][]rawCase{}
	for _, c := range raw {
		hosts, rules := evHostsRules(c.evs)
		crit := in.Criteria.criterionOf(c.pattern, rules)
		if crit == "" { // rule not linked to a criterion
			crit = "rule=" + strings.Join(rules, ",")
		}
		actor := c.sig.actor
		if actor == "" {
			actor = "host:" + hosts[0]
		}
		hay := []string{c.entity, actor}
		hay = append(hay, hosts...)
		for _, r := range rules {
			hay = append(hay, "rule="+r)
		}
		text := strings.Join(hay, " ")
		for i := range known {
			k := &known[i]
			if (k.Pattern == "" || k.Pattern == "*" || k.Pattern == c.pattern || k.Pattern == crit) && k.re.MatchString(text) {
				c.hit = k
				break
			}
		}
		k := key{crit, actor}
		if _, ok := parts[k]; !ok {
			order = append(order, k)
		}
		parts[k] = append(parts[k], c)
	}

	type built struct {
		c   Case
		evs []ev
	}
	rows := []built{}
	for _, k := range order {
		ps := parts[k]
		var live []rawCase
		for _, p := range ps {
			if p.hit == nil {
				live = append(live, p)
			}
		}
		var hit *KnownActivity
		use := live
		if len(live) == 0 {
			use, hit = ps, ps[0].hit
		}
		use = append([]rawCase(nil), use...)
		sort.SliceStable(use, func(i, j int) bool { return use[i].score > use[j].score })
		pattern, score := use[0].pattern, use[0].score

		ents, summs := []string{}, []string{}
		sig := signals{}
		why := map[string]bool{}
		seen := map[*Alert]bool{}
		var evs []ev
		for _, p := range use {
			ents, summs = append(ents, p.entity), append(summs, p.summary)
			for _, w := range p.sig.why {
				why[w] = true
			}
			sig.priv, sig.attack = sig.priv || p.sig.priv, sig.attack || p.sig.attack
			for _, e := range p.evs {
				if !seen[e.a] {
					seen[e.a] = true
					evs = append(evs, e)
				}
			}
		}
		sig.why = sortedSet(why)
		evs = byTime(evs)
		entity := strings.Join(uniq(ents), " / ")
		summary := clip(strings.Join(uniq(summs), " / "), 300)
		if len(live) > 0 && len(use) < len(ps) {
			summary += fmt.Sprintf(" · 정상 업무 일치 %d건 제외", len(ps)-len(use))
		}
		hosts, rules := evHostsRules(evs)
		attack := map[string]bool{}
		for _, r := range rules {
			for _, t := range strings.Split(in.Catalog[r].Attack, ",") {
				if t != "" {
					attack[t] = true
				}
			}
		}
		weak := map[string]bool{}
		for _, h := range hosts {
			for _, code := range posturePattern[pattern] {
				if in.Posture[h][code] && (code != "U-01" || strings.Contains(entity, "user=root") || contains(rules, "100904")) {
					weak[code] = true
				}
			}
		}
		if len(weak) > 0 {
			score += 10 * len(weak)
			summary += " · 연계: " + strings.Join(sortedSet(weak), ",")
		}
		sev, basis := caseSeverity(pattern, sig, evs, in.Admin, hit != nil)
		c := Case{Pattern: pattern, Score: score, Entity: entity, Hosts: hosts, First: evs[0].t, Last: evs[len(evs)-1].t, N: len(evs),
			Attack: sortedSet(attack), Summary: summary, Severity: sev, SevBasis: basis, Criterion: k.crit, Title: in.Criteria.Title[k.crit], Actor: k.actor}
		if hit != nil {
			c.Score, c.Known = 0, hit.Reason
		}
		rows = append(rows, built{c, evs})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].c.Score != rows[j].c.Score {
			return rows[i].c.Score > rows[j].c.Score
		}
		return rows[i].c.First.Before(rows[j].c.First)
	})

	out := make([]Case, len(rows))
	times := make([][]time.Time, len(rows))
	for i, r := range rows {
		c := r.c
		c.ID = fmt.Sprintf("CASE-%03d", i+1)
		shown := r.evs
		if len(shown) > timelineMax {
			shown = append(append([]ev{}, r.evs[:timelineMax/2]...), r.evs[len(r.evs)-timelineMax/2:]...)
		}
		c.Timeline = make([]CaseEvent, len(shown))
		for j, e := range shown {
			c.Timeline[j] = CaseEvent{T: e.t, Host: e.a.Host, Rule: e.a.RuleID, Level: e.a.Level, Actor: e.a.Actor, Src: e.a.Src, Object: e.a.Object, Desc: e.a.Desc}
		}
		for j, e := range r.evs { // distinct, ascending
			if j == 0 || !e.t.Equal(r.evs[j-1].t) {
				times[i] = append(times[i], e.t)
			}
		}
		out[i] = c
	}
	// temporal neighbours: same operator or same intrusion
	for i := range out {
		out[i].Near = []string{}
		for j := range out {
			if i != j && timesNear(times[i], times[j]) {
				out[i].Near = append(out[i].Near, out[j].ID)
			}
		}
	}
	return out
}

// timesNear reports whether any two instants of the ascending lists are
// within nearGap of each other.
func timesNear(a, b []time.Time) bool {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		d := a[i].Sub(b[j])
		if d < 0 {
			d = -d
		}
		if d <= nearGap {
			return true
		}
		if a[i].Before(b[j]) {
			i++
		} else {
			j++
		}
	}
	return false
}
