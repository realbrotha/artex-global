package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/wazuh"
)

// fakeRunner installs a stand-in CLI that records its arguments and input
// and prints the given JSON.
func fakeRunner(t *testing.T, output string, exit int) (argsFile, stdinFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile, stdinFile = filepath.Join(dir, "args"), filepath.Join(dir, "stdin")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'fake 1.0'; exit 0; fi\n" +
		"printf '%s\\n' \"$@\" > " + argsFile + "\ncat > " + stdinFile + "\ncat <<'JSON'\n" + output + "\nJSON\nexit " + string(rune('0'+exit)) + "\n"
	path := filepath.Join(dir, "fake-claude")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	old := runnerCommand
	runnerCommand = path
	runnerInfo.Lock()
	runnerInfo.at = time.Time{}
	runnerInfo.Unlock()
	t.Cleanup(func() {
		runnerCommand = old
		runnerInfo.Lock()
		runnerInfo.at = time.Time{}
		runnerInfo.Unlock()
	})
	return argsFile, stdinFile
}

func TestRunnerCompleter(t *testing.T) {
	argsFile, stdinFile := fakeRunner(t, `{"result":"판정 결과","is_error":false,"usage":{"input_tokens":10,"output_tokens":5}}`, 0)
	s := &Server{m: &Manager{}}
	text, err := s.runnerCompleter("sonnet")(context.Background(), "시스템 규칙", "사건 JSON", 100)
	if err != nil || text != "판정 결과" {
		t.Fatalf("text=%q err=%v", text, err)
	}
	args, _ := os.ReadFile(argsFile)
	for _, want := range []string{"-p", "--output-format", "json", "--system-prompt", "시스템 규칙", "--tools", "--no-session-persistence", "--model", "sonnet"} {
		if !strings.Contains(string(args), want+"\n") {
			t.Errorf("argument %q missing: %s", want, args)
		}
	}
	// The case data travels on standard input, never on the command line.
	if strings.Contains(string(args), "사건 JSON") {
		t.Error("the user prompt must not be a command-line argument")
	}
	if in, _ := os.ReadFile(stdinFile); string(in) != "사건 JSON" {
		t.Errorf("stdin = %q", in)
	}
	if path, version := runnerStatus(); path == "" || version != "fake 1.0" {
		t.Errorf("status = %q %q", path, version)
	}
}

func TestRunnerCompleterFailures(t *testing.T) {
	s := &Server{m: &Manager{}}
	fakeRunner(t, `{"result":"Failed to authenticate","is_error":true}`, 0)
	if _, err := s.runnerCompleter("")(context.Background(), "s", "u", 1); !errors.Is(err, errRunner) || !strings.Contains(err.Error(), "authenticate") {
		t.Errorf("sign-in failure: %v", err)
	}
	fakeRunner(t, `not json`, 1)
	if _, err := s.runnerCompleter("")(context.Background(), "s", "u", 1); !errors.Is(err, errRunner) {
		t.Errorf("bad output: %v", err)
	}
	// A runner failure is a failed call, not a judgment: it reaches the
	// caller as an error so the case stays unjudged.
	if status, msg := judgeFailure(errRunner); status != 502 || msg == "" {
		t.Errorf("judgeFailure = %d %q", status, msg)
	}
}

func TestJudgeBackendFallsBackWithoutRunner(t *testing.T) {
	old := runnerCommand
	runnerCommand = "no-such-runner-command"
	runnerInfo.Lock()
	runnerInfo.at = time.Time{}
	runnerInfo.Unlock()
	defer func() {
		runnerCommand = old
		runnerInfo.Lock()
		runnerInfo.at = time.Time{}
		runnerInfo.Unlock()
	}()
	s := &Server{m: &Manager{}}
	sched := wazuh.DefaultSchedule()
	sched.JudgeMode = wazuh.JudgeRunner
	if complete, _, msg := s.judgeBackend(sched); complete != nil || msg == "" {
		t.Errorf("no runner and no API profile must be refused, got msg=%q", msg)
	}
	for _, bad := range []string{"a b", "x;rm", strings.Repeat("m", 61), "모델"} {
		if runnerModelRe.MatchString(bad) {
			t.Errorf("model name %q must be rejected", bad)
		}
	}
	if !runnerModelRe.MatchString("claude-sonnet-5-5") || !runnerModelRe.MatchString("") {
		t.Error("plain model names must pass")
	}
}
