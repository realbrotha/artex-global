package wazuh

import (
	"sort"
	"strings"
)

// Feedback inputs: what the verdict store, the judgment records and the
// corrections say about one connection. Case keys are "criterion|actor".
type (
	// FeedbackVerdict is the current verdict of one case.
	FeedbackVerdict struct {
		CaseKey string
		Verdict string
		Method  string
	}
	// FeedbackJudgement is one recorded model judgment.
	FeedbackJudgement struct {
		CaseKey string
		Verdict string // "" when it failed
		Method  string
	}
	// FeedbackCorrection is one verdict a person changed.
	FeedbackCorrection struct {
		CaseKey string
		From    string
		To      string
	}
)

// CriterionFeedback is one detection criterion's verdict record.
type CriterionFeedback struct {
	Criterion string         `json:"criterion"`
	Title     string         `json:"title"`
	Cases     int            `json:"cases"`
	Verdicts  map[string]int `json:"verdicts"`
	// Model judgments recorded, and how many needed a debate or a fallback.
	Judgements int `json:"judgements"`
	Debated    int `json:"debated"`
	Fallback   int `json:"fallback"`
	// Verdicts a person changed.
	Corrected int `json:"corrected"`
}

// Signal kinds.
const (
	SignalFalsePositive = "false_positive_heavy" // the criterion mostly misfires
	SignalNormalRepeat  = "normal_repeat"        // one subject keeps being judged normal
	SignalUnstable      = "unstable"             // the model keeps needing debates or fallbacks
	SignalCorrected     = "corrected"            // people keep overruling the model
)

// Signal thresholds (Thaki-Siem rule_feedback defaults where they exist).
const (
	signalMinCases     = 5
	signalNormalRepeat = 3
	signalMinJudged    = 3
	signalCorrections  = 2
)

// FeedbackSignal is one suggestion for the detection rules or the model.
type FeedbackSignal struct {
	Kind      string `json:"kind"`
	Criterion string `json:"criterion"`
	Title     string `json:"title"`
	// Set for a subject-level signal (normal repeat).
	CaseKey string `json:"case_key,omitempty"`
	Count   int    `json:"count"`
	Of      int    `json:"of"`
}

func criterionOf(key string) string {
	criterion, _, _ := strings.Cut(key, "|")
	return criterion
}

// SummarizeFeedback folds a connection's verdict record into one row per
// criterion and the signals worth acting on. titles maps criterion codes to
// readable titles.
func SummarizeFeedback(verdicts []FeedbackVerdict, judgements []FeedbackJudgement, corrections []FeedbackCorrection, titles map[string]string) ([]CriterionFeedback, []FeedbackSignal) {
	rows := map[string]*CriterionFeedback{}
	row := func(key string) *CriterionFeedback {
		c := criterionOf(key)
		r := rows[c]
		if r == nil {
			r = &CriterionFeedback{Criterion: c, Title: titles[c], Verdicts: map[string]int{}}
			rows[c] = r
		}
		return r
	}
	for _, v := range verdicts {
		r := row(v.CaseKey)
		r.Cases++
		r.Verdicts[v.Verdict]++
	}
	normals := map[string]int{}
	for _, j := range judgements {
		r := row(j.CaseKey)
		r.Judgements++
		switch j.Method {
		case MethodDebate:
			r.Debated++
		case MethodFallback:
			r.Fallback++
		}
		if j.Verdict == VerdictNormal {
			normals[j.CaseKey]++
		}
	}
	for _, c := range corrections {
		row(c.CaseKey).Corrected++
	}

	signals := []FeedbackSignal{}
	for _, r := range rows {
		if fp := r.Verdicts[VerdictFalsePositive]; r.Cases >= signalMinCases && fp*2 > r.Cases {
			signals = append(signals, FeedbackSignal{Kind: SignalFalsePositive, Criterion: r.Criterion, Title: r.Title, Count: fp, Of: r.Cases})
		}
		if hard := r.Debated + r.Fallback; r.Judgements >= signalMinJudged && hard*2 >= r.Judgements {
			signals = append(signals, FeedbackSignal{Kind: SignalUnstable, Criterion: r.Criterion, Title: r.Title, Count: hard, Of: r.Judgements})
		}
		if r.Corrected >= signalCorrections {
			signals = append(signals, FeedbackSignal{Kind: SignalCorrected, Criterion: r.Criterion, Title: r.Title, Count: r.Corrected, Of: r.Cases})
		}
	}
	for key, n := range normals {
		if n >= signalNormalRepeat {
			c := criterionOf(key)
			signals = append(signals, FeedbackSignal{Kind: SignalNormalRepeat, Criterion: c, Title: titles[c], CaseKey: key, Count: n})
		}
	}

	out := make([]CriterionFeedback, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Cases != out[j].Cases {
			return out[i].Cases > out[j].Cases
		}
		return out[i].Criterion < out[j].Criterion
	})
	rank := map[string]int{SignalCorrected: 0, SignalFalsePositive: 1, SignalUnstable: 2, SignalNormalRepeat: 3}
	sort.Slice(signals, func(i, j int) bool {
		a, b := signals[i], signals[j]
		if rank[a.Kind] != rank[b.Kind] {
			return rank[a.Kind] < rank[b.Kind]
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Criterion+a.CaseKey < b.Criterion+b.CaseKey
	})
	return out, signals
}
