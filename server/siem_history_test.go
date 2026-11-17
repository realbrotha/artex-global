package server

import (
	"context"
	"errors"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/wazuh"
)

func TestRecordingCompleterKeepsEveryAttempt(t *testing.T) {
	answers := []string{"not json", `{"verdict":"normal"}`}
	calls := 0
	inner := func(_ context.Context, _, _ string, _ int) (string, error) {
		calls++
		if calls > len(answers) {
			return "", errors.New("provider down")
		}
		return answers[calls-1], nil
	}
	var system string
	var attempts []db.JudgeAttempt
	complete := recordingCompleter(inner, &system, &attempts)

	for _, prompt := range []string{"first", "second", "third"} {
		_, _ = complete(context.Background(), "rules", prompt, 100)
	}
	if system != "rules" || len(attempts) != 3 {
		t.Fatalf("system=%q attempts=%d", system, len(attempts))
	}
	if attempts[0].Prompt != "first" || attempts[0].Response != "not json" || attempts[0].Error != "" {
		t.Errorf("first attempt = %+v", attempts[0])
	}
	if attempts[1].Response != `{"verdict":"normal"}` {
		t.Errorf("second attempt = %+v", attempts[1])
	}
	// A failed request is recorded too, with its error.
	if attempts[2].Prompt != "third" || attempts[2].Error != "provider down" {
		t.Errorf("third attempt = %+v", attempts[2])
	}
}

func TestResearchIsRecordedAsItsOwnEntry(t *testing.T) {
	record := db.Judgement{}
	addResearch(&record, wazuh.AutoResult{})
	if len(record.Attempts) != 0 {
		t.Fatal("no research, no entry")
	}
	addResearch(&record, wazuh.AutoResult{ResearchQuery: "ATT&CK: T1021", ResearchNotes: ""})
	addResearch(&record, wazuh.AutoResult{ResearchQuery: "ATT&CK: T1021", ResearchNotes: "설명"})
	if len(record.Attempts) != 2 || record.Attempts[0].Role != "research" || record.Attempts[0].Response != "찾은 자료 없음" || record.Attempts[1].Response != "설명" {
		t.Errorf("attempts = %+v", record.Attempts)
	}
	// Only a technique id may go into an outside request.
	for id, ok := range map[string]bool{"T1021": true, "T1021.004": true, "T1021/../x": false, "web01": false, "10.0.0.1": false, "": false} {
		if attackID.MatchString(id) != ok {
			t.Errorf("attackID(%q) = %v", id, !ok)
		}
	}
}
