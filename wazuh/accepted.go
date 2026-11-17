package wazuh

import (
	"bufio"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// AcceptedRisk is one approved exception: check code on one host (or every
// host with "*"), valid until a date. Same format as Thaki-Siem
// registry/accepted-risks.tsv.
type AcceptedRisk struct {
	Code       string `json:"code"`
	Host       string `json:"host"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
	Until      string `json:"until"` // YYYY-MM-DD; empty = no expiry
}

// Acceptance is the registry row that covers an issue.
type Acceptance struct {
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
	Until      string `json:"until,omitempty"`
	Host       string `json:"host"` // "*" when the row covers every host
}

var acceptedHeader = []string{"code", "host", "reason", "approved_by", "until"}

const maxAcceptedRisks = 5000

// ValidateAcceptedRisk trims and checks one row.
func ValidateAcceptedRisk(r AcceptedRisk) (AcceptedRisk, error) {
	r.Code, r.Host = strings.TrimSpace(r.Code), strings.TrimSpace(r.Host)
	r.Reason, r.ApprovedBy, r.Until = strings.TrimSpace(r.Reason), strings.TrimSpace(r.ApprovedBy), strings.TrimSpace(r.Until)
	switch {
	case r.Code == "" || utf8.RuneCountInString(r.Code) > 100:
		return r, invalid("점검 코드가 비어 있거나 너무 깁니다")
	case r.Host == "" || utf8.RuneCountInString(r.Host) > 255:
		return r, invalid("장비가 비어 있거나 너무 깁니다 (전체는 *)")
	case r.Reason == "" || utf8.RuneCountInString(r.Reason) > 2000:
		return r, invalid("수용 근거가 비어 있거나 너무 깁니다")
	case r.ApprovedBy == "" || utf8.RuneCountInString(r.ApprovedBy) > 100:
		return r, invalid("승인자가 비어 있거나 너무 깁니다")
	}
	if r.Until != "" {
		if _, err := time.Parse("2006-01-02", r.Until); err != nil {
			return r, invalid("만료일은 YYYY-MM-DD 형식이어야 합니다")
		}
	}
	return r, nil
}

// ParseAcceptedRisks reads the registry TSV. Comment lines start with '#';
// the first other line must be the header.
func ParseAcceptedRisks(tsv string) ([]AcceptedRisk, error) {
	out := []AcceptedRisk{}
	sc := bufio.NewScanner(strings.NewReader(tsv))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	header := false
	seen := map[[2]string]int{}
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if !header {
			if len(cols) != len(acceptedHeader) {
				return nil, invalid(fmt.Sprintf("%d줄: 헤더는 %s 이어야 합니다", n, strings.Join(acceptedHeader, "\\t")))
			}
			for i, h := range acceptedHeader {
				if strings.TrimSpace(cols[i]) != h {
					return nil, invalid(fmt.Sprintf("%d줄: 헤더는 %s 이어야 합니다", n, strings.Join(acceptedHeader, "\\t")))
				}
			}
			header = true
			continue
		}
		if len(cols) != len(acceptedHeader) {
			return nil, invalid(fmt.Sprintf("%d줄: 열 %d개 (필요 %d, 탭 구분)", n, len(cols), len(acceptedHeader)))
		}
		r, err := ValidateAcceptedRisk(AcceptedRisk{Code: cols[0], Host: cols[1], Reason: cols[2], ApprovedBy: cols[3], Until: cols[4]})
		if err != nil {
			return nil, fmt.Errorf("%d줄: %w", n, err)
		}
		key := [2]string{r.Code, strings.ToLower(r.Host)}
		if prev, dup := seen[key]; dup {
			return nil, invalid(fmt.Sprintf("%d줄: %d줄과 같은 코드·장비", n, prev))
		}
		seen[key] = n
		out = append(out, r)
		if len(out) > maxAcceptedRisks {
			return nil, invalid(fmt.Sprintf("등록은 %d건까지 가능합니다", maxAcceptedRisks))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, invalid("파일을 읽지 못했습니다")
	}
	if !header {
		return nil, invalid("헤더 줄이 없습니다")
	}
	return out, nil
}

// cisKeyPrefix maps a config-check CIS policy to its registry code prefix
// (Thaki-Siem tools/config-check/config_check/data/cis_policies.tsv).
func cisKeyPrefix(policy string) string {
	switch {
	case policy == "cis_docker":
		return "CIS-Docker "
	case strings.HasPrefix(policy, "cis_"):
		return "CIS "
	default:
		return "CIS-K8s "
	}
}

// RegistryCode is the code an issue is registered under: CIS checks carry a
// policy prefix ("CIS 6.3.1", "CIS-K8s 1.2.1"), everything else is the code.
func RegistryCode(std, policy, code string) string {
	if std == "cis" {
		return cisKeyPrefix(policy) + code
	}
	return code
}

// acceptanceIndex resolves (code, host) to a registry row. A host row wins
// over a "*" row; expired rows are skipped.
type acceptanceIndex map[[2]string]Acceptance

func newAcceptanceIndex(risks []AcceptedRisk, today time.Time) acceptanceIndex {
	day := today.Format("2006-01-02")
	idx := acceptanceIndex{}
	for _, r := range risks {
		if r.Until != "" && r.Until < day {
			continue
		}
		host := r.Host
		if host != "*" {
			host = shortName(host)
		}
		idx[[2]string{r.Code, host}] = Acceptance{Reason: r.Reason, ApprovedBy: r.ApprovedBy, Until: r.Until, Host: r.Host}
	}
	return idx
}

func (idx acceptanceIndex) lookup(code, agent string) *Acceptance {
	if a, ok := idx[[2]string{code, shortName(agent)}]; ok {
		return &a
	}
	if a, ok := idx[[2]string{code, "*"}]; ok {
		return &a
	}
	return nil
}
