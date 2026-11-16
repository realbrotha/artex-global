package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/investigation"
)

// Helpers shared by the Defensive hunting and log-connection handlers.

type investigationQueryProof struct {
	Search     agent.InvestigationSearch `json:"search"`
	Collection investigation.Collection  `json:"collection"`
}

// decodePurpleRequestLimit decodes exactly one JSON object with no unknown
// fields from a body capped at limit bytes.
func decodePurpleRequestLimit(w http.ResponseWriter, r *http.Request, target any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(target)
	if err == nil {
		var extra any
		if err = decoder.Decode(&extra); err == io.EOF {
			return true
		}
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("요청 본문은 %d KiB 이하여야 합니다", limit/1024))
	} else {
		writeErr(w, http.StatusBadRequest, "올바른 JSON 객체와 필드를 입력해 주세요")
	}
	return false
}

func boundDefensiveCaseMarkers(c *investigation.Collection, runs []db.InvestigationVerification) {
	originalWarnings := len(c.Warnings)
	boundInvestigationMarkers(c, runs)
	if len(c.Warnings) > originalWarnings && c.Stats.KnownARTEX > 0 {
		c.Warnings[len(c.Warnings)-1] = "ARTEX 구분은 전체 등록 검증 실행 ID와 실제 실행 시간 구간 일치에 근거합니다. 표식은 인증 수단이 아니므로 원본 요청·점검 일정과 대조하세요."
	}
}

// boundInvestigationMarkers keeps an ARTEX marker only when its ID and
// timestamp match a known verification run.
func boundInvestigationMarkers(c *investigation.Collection, runs []db.InvestigationVerification) {
	for i := range c.Events {
		event := &c.Events[i]
		if !event.KnownARTEX {
			continue
		}
		matched := false
		for _, run := range runs {
			if strings.EqualFold(run.ID, event.VerificationID) && !event.Timestamp.Before(run.Start) && event.Timestamp.Before(run.End) {
				matched = true
				break
			}
		}
		if !matched {
			event.KnownARTEX = false
			c.Stats.KnownARTEX--
			c.Stats.UnrecognizedMarkers++
		}
	}
	if c.Stats.KnownARTEX > 0 {
		c.Warnings = append(c.Warnings, "ARTEX 구분은 같은 취약점의 등록 실행 ID와 시간 구간 일치에 근거합니다. 표식은 인증 수단이 아니므로 원본 요청·점검 일정과 대조하세요.")
	}
}

// validateInvestigationPivot rejects follow-up searches that widen the
// confirmed target, time window or path scope.
func validateInvestigationPivot(base investigation.Scope, query agent.InvestigationSearch) error {
	if err := investigation.ValidateScope(query.Scope, time.Now()); err != nil {
		return err
	}
	if query.Scope.Target != base.Target || query.Scope.Start.Before(base.Start) || query.Scope.End.After(base.End) {
		return fmt.Errorf("조사 대상 또는 시간 범위를 넓힐 수 없습니다")
	}
	if base.PathPrefix != "" && base.PathPrefix != "/" && !investigation.MatchPath(query.Scope.PathPrefix, base.PathPrefix) {
		return fmt.Errorf("조사 경로 범위를 넓힐 수 없습니다")
	}
	if !query.Remote || query.Offset != 0 {
		return fmt.Errorf("원격 조회는 첫 페이지의 범위 제한 검색만 지원합니다")
	}
	return nil
}
