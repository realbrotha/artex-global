package server

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"sync/atomic"

	"github.com/Autumn-27/norma/llm"
)

// These responses exercise the real planner/worker harness and server callback;
// neither the model provider nor the Splunk endpoint makes an external call.
type investigationSplunkRunProvider struct {
	calls        atomic.Int32
	beforeSearch func() error
	revoked      bool
	ref          string
}

func (p *investigationSplunkRunProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if err := ctx.Err(); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	n := p.calls.Add(1)
	tool, input := "", ""
	switch n {
	case 1:
		tool, input = "plan_investigation", `{"action":"investigate","reason":"추가 원본 로그를 확인합니다.","hypothesis":"공개 파일에 대한 후속 접근이 있을 수 있습니다.","objective":"지정한 출발지의 후속 파일 요청을 확인합니다."}`
	case 2:
		if p.beforeSearch != nil {
			if err := p.beforeSearch(); err != nil {
				return llm.Message{}, "", llm.Usage{}, err
			}
		}
		tool, input = "search_evidence", `{"remote":true,"source_ip":"192.0.2.44","path_contains":"followup.txt"}`
	case 3:
		if p.revoked {
			tool, input = "record_observation", `{"kind":"insufficient_data","summary":"연결 설정 변경으로 후속 로그를 조회하지 못했습니다.","next_steps":["최신 연결로 로그 근거를 다시 준비하세요."]}`
		} else {
			body, err := json.Marshal(req.Messages)
			if err != nil {
				return llm.Message{}, "", llm.Usage{}, err
			}
			var value any
			if err = json.Unmarshal(body, &value); err != nil {
				return llm.Message{}, "", llm.Usage{}, err
			}
			p.ref = investigationSplunkRunRef(value)
			if p.ref == "" {
				return llm.Message{}, "", llm.Usage{}, fmt.Errorf("remote event missing from worker search result")
			}
			tool, input = "read_evidence", fmt.Sprintf(`{"refs":[%q]}`, p.ref)
		}
	case 4:
		if !p.revoked {
			body, _ := json.Marshal(req.Messages)
			if !strings.Contains(string(body), "original-remote-evidence-marker") {
				return llm.Message{}, "", llm.Usage{}, fmt.Errorf("worker did not read original remote event")
			}
			tool, input = "record_observation", fmt.Sprintf(`{"kind":"observed","summary":"지정한 출발지의 파일 요청이 기록되었습니다. 실제 내용 탈취 여부는 확인되지 않습니다.","evidence_refs":[%q],"alternatives":["승인된 정상 접근일 수 있습니다."],"next_steps":["인증 기록을 대조하세요."]}`, p.ref)
		}
	case 5:
		if p.revoked {
			tool, input = "plan_investigation", `{"action":"insufficient_data","reason":"연결 변경으로 후속 로그 확인을 완료하지 못했습니다.","needed_logs":["최신 연결에서 다시 수집한 원본 로그"]}`
		} else {
			tool, input = "plan_investigation", fmt.Sprintf(`{"action":"complete","reason":"허용된 범위의 후속 접근을 원본으로 확인했습니다.","evidence_refs":[%q]}`, p.ref)
		}
	default:
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("unexpected provider call %d", n)
	}
	usage := llm.Usage{InputTokens: 12, OutputTokens: 8}
	if tool == "" {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("단계를 마쳤습니다.")}}, "end_turn", usage, nil
	}
	// Assert the shortened sequence still crosses the real planner/worker
	// boundary; a stale scripted response must not pass in the wrong stage.
	available := false
	for _, definition := range req.Tools {
		available = available || definition.Name == tool
	}
	if !available {
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("call %d expected %s in the current investigation stage", n, tool)
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: fmt.Sprintf("remote-step-%d", n), Name: tool, Input: json.RawMessage(input)}}}, "tool_use", usage, nil
}
func (p *investigationSplunkRunProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, fmt.Errorf("test provider requires non-streaming configuration"))
	}
}

// Tool outputs are JSON strings nested inside provider message content. Recover
// only the actual returned event ref rather than inventing a citation in tests.
func investigationSplunkRunRef(value any) string {
	switch v := value.(type) {
	case map[string]any:
		if v["id"] == "remote-followup" {
			if ref, ok := v["ref"].(string); ok {
				return ref
			}
		}
		for _, child := range v {
			if ref := investigationSplunkRunRef(child); ref != "" {
				return ref
			}
		}
	case []any:
		for _, child := range v {
			if ref := investigationSplunkRunRef(child); ref != "" {
				return ref
			}
		}
	case string:
		var nested any
		if len(v) > 0 && (v[0] == '{' || v[0] == '[') && json.Unmarshal([]byte(v), &nested) == nil {
			return investigationSplunkRunRef(nested)
		}
	}
	return ""
}

