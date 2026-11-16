package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

// Shared Defensive (hunting / log connection) storage errors.
var (
	ErrDefenseConflict = errors.New("방어 계획 또는 원본 증거가 변경됐습니다. 새로고침 후 다시 저장해 주세요")
	ErrDefenseInvalid  = errors.New("방어 검증 입력이 올바르지 않습니다")
)

// InvestigationVerification is a known ARTEX verification run whose
// correlation ID marks its own traffic inside collected logs.
type InvestigationVerification struct {
	ID         string
	Start, End time.Time
}

// KnownDefensiveVerifications returns ARTEX verification runs overlapping the
// scope. This build has no correlation-tagged defense executions, so there is
// no ARTEX-originated traffic to mark and the result is always empty.
func (d *DB) KnownDefensiveVerifications(_ context.Context, _ investigation.Scope) ([]InvestigationVerification, error) {
	return []InvestigationVerification{}, nil
}

func investigationRunObject(raw json.RawMessage, maxBytes int) (json.RawMessage, error) {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	var object map[string]json.RawMessage
	if len(raw) > maxBytes || json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, fmt.Errorf("%w: 조사 실행 데이터는 크기 제한 안의 JSON 객체여야 합니다", ErrDefenseInvalid)
	}
	return raw, nil
}
