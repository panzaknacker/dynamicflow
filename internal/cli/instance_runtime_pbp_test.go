package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/instanceclient"
	"dynamicflow/internal/serving"
)

func TestPBPRuntimeBridgeNormalizesWithoutLeakingAndDeduplicates(t *testing.T) {
	fixture := newPBPRuntimeBridgeFixture(t)
	secret := "token=SUPER-SECRET argv=--password /home/malwarelab/profile https://secret.example/a 203.0.113.7"
	fixture.writeLog(t, "runtime-20260723T120000Z-101-00000001.jsonl",
		`{"timestamp":"2026-07-23T12:00:00Z","event":"runtime.stderr","message":"`+secret+`"}`+"\n"+
			`{"event":"launch.begin","desktop":true,"url_supplied":true,"persona":"`+secret+`"}`+"\n"+
			`{"event":"browser.page_crashed","detail":"`+secret+`"}`)

	client := &fakeRuntimeClient{}
	fixture.run(t, client)
	if len(client.logs) != 1 || client.logs[0].Events[0].Event != "pbp_launch_started" {
		t.Fatalf("first pass logs=%#v", client.logs)
	}
	fixture.appendLog(t, "runtime-20260723T120000Z-101-00000001.jsonl",
		"\n"+`{"event":"launch.end","reason":"browser_crash","error":"`+secret+`"}`+"\n")
	fixture.run(t, client)
	if got := flattenedPBPEvents(client.logs); !reflect.DeepEqual(got, []string{
		"pbp_launch_started", "pbp_browser_crashed", "pbp_launch_ended:browser_crash",
	}) {
		t.Fatalf("normalized events=%v", got)
	}
	fixture.run(t, client)
	if len(flattenedPBPEvents(client.logs)) != 3 {
		t.Fatalf("completed lines were uploaded twice: %#v", client.logs)
	}
	encoded, err := json.Marshal(client.logs)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"SUPER-SECRET", "--password", "/home/malwarelab", "secret.example", "203.0.113.7", "persona", "argv"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("uploaded log leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestPBPRuntimeBridgeRetriesPendingWithSameSequence(t *testing.T) {
	fixture := newPBPRuntimeBridgeFixture(t)
	fixture.writeLog(t, "runtime-20260723T120001Z-102-00000002.jsonl", `{"event":"launch.begin"}`+"\n")
	client := &fakeRuntimeClient{logErr: errors.New("network unavailable")}
	if err := fixture.runError(client); err == nil {
		t.Fatal("failed upload unexpectedly succeeded")
	}
	if len(client.logs) != 1 {
		t.Fatalf("first attempts=%d", len(client.logs))
	}
	first := client.logs[0].Events[0]
	client.logErr = nil
	fixture.run(t, client)
	if len(client.logs) != 2 || client.logs[1].Events[0] != first {
		t.Fatalf("pending retry changed identity: %#v", client.logs)
	}
	fixture.run(t, client)
	if len(client.logs) != 2 {
		t.Fatalf("successful pending event replayed: %#v", client.logs)
	}
}

func TestPBPRuntimeBridgeRejectsUnsafeSourcesAndBounds(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func(*testing.T, pbpRuntimeBridgeFixture)
	}{
		{name: "symlink", build: func(t *testing.T, fixture pbpRuntimeBridgeFixture) {
			target := filepath.Join(fixture.home, "target")
			if err := os.WriteFile(target, []byte(`{"event":"launch.begin"}`+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(fixture.logs, "runtime-20260723T120002Z-103-00000003.jsonl")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hardlink", build: func(t *testing.T, fixture pbpRuntimeBridgeFixture) {
			fixture.writeLog(t, "runtime-20260723T120003Z-104-00000004.jsonl", `{"event":"launch.begin"}`+"\n")
			if err := os.Link(filepath.Join(fixture.logs, "runtime-20260723T120003Z-104-00000004.jsonl"), filepath.Join(fixture.home, "second-link")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "oversize", build: func(t *testing.T, fixture pbpRuntimeBridgeFixture) {
			path := filepath.Join(fixture.logs, "runtime-20260723T120004Z-105-00000005.jsonl")
			file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(pbpRuntimeLogMaxBytes + 1); err != nil {
				t.Fatal(err)
			}
			file.Close()
		}},
		{name: "wrong-mode", build: func(t *testing.T, fixture pbpRuntimeBridgeFixture) {
			fixture.writeLog(t, "runtime-20260723T120005Z-106-00000006.jsonl", `{"event":"launch.begin"}`+"\n")
			if err := os.Chmod(filepath.Join(fixture.logs, "runtime-20260723T120005Z-106-00000006.jsonl"), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPBPRuntimeBridgeFixture(t)
			test.build(t, fixture)
			client := &fakeRuntimeClient{}
			if err := fixture.runError(client); err == nil || len(client.logs) != 0 {
				t.Fatalf("unsafe source err=%v logs=%#v", err, client.logs)
			}
		})
	}
}

func TestPBPRuntimeBridgeSkipsOversizeLinesAndWaitsForPartialLine(t *testing.T) {
	fixture := newPBPRuntimeBridgeFixture(t)
	name := "runtime-20260723T120006Z-107-00000007.jsonl"
	fixture.writeLog(t, name,
		`{"event":"launch.begin","junk":"`+strings.Repeat("x", pbpRuntimeLogMaxLineBytes)+`"}`+"\n"+
			`{"event":"browser.context_started"}`)
	client := &fakeRuntimeClient{}
	fixture.run(t, client)
	if len(client.logs) != 0 {
		t.Fatalf("oversize or partial line uploaded: %#v", client.logs)
	}
	fixture.appendLog(t, name, "\n")
	fixture.run(t, client)
	if got := flattenedPBPEvents(client.logs); !reflect.DeepEqual(got, []string{"pbp_browser_started"}) {
		t.Fatalf("completed partial line=%v", got)
	}
}

func TestPBPRuntimeBridgeHandlesRotationReplacementAndTruncationWithoutReplay(t *testing.T) {
	fixture := newPBPRuntimeBridgeFixture(t)
	first := "runtime-20260723T120007Z-108-00000008.jsonl"
	fixture.writeLog(t, first, `{"event":"launch.begin"}`+"\n")
	client := &fakeRuntimeClient{}
	fixture.run(t, client)

	if err := os.Remove(filepath.Join(fixture.logs, first)); err != nil {
		t.Fatal(err)
	}
	fixture.writeLog(t, first, `{"event":"browser.page_crashed"}`+"\n")
	second := "runtime-20260723T120008Z-109-00000009.jsonl"
	fixture.writeLog(t, second, `{"event":"browser.context_started"}`+"\n")
	fixture.run(t, client)
	if got := flattenedPBPEvents(client.logs); !reflect.DeepEqual(got, []string{"pbp_launch_started", "pbp_browser_started"}) {
		t.Fatalf("replacement was replayed or rotation missed: %v", got)
	}

	if err := os.Truncate(filepath.Join(fixture.logs, second), 0); err != nil {
		t.Fatal(err)
	}
	fixture.appendLog(t, second, `{"event":"browser.page_crashed"}`+"\n")
	fixture.run(t, client)
	if len(flattenedPBPEvents(client.logs)) != 2 {
		t.Fatalf("truncated source replayed: %#v", client.logs)
	}
}

func TestPBPRuntimeBridgeSerializesConcurrentTimerRuns(t *testing.T) {
	fixture := newPBPRuntimeBridgeFixture(t)
	fixture.writeLog(t, "runtime-20260723T120009Z-110-0000000a.jsonl", `{"event":"launch.begin"}`+"\n")
	clients := []*fakeRuntimeClient{{}, {}}
	start := make(chan struct{})
	results := make(chan error, len(clients))
	var wait sync.WaitGroup
	for _, client := range clients {
		wait.Add(1)
		go func(client *fakeRuntimeClient) {
			defer wait.Done()
			<-start
			results <- fixture.runError(client)
		}(client)
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(clients[0].logs)+len(clients[1].logs) != 1 {
		t.Fatalf("concurrent runs duplicated event: left=%#v right=%#v", clients[0].logs, clients[1].logs)
	}
}

func TestInstanceRuntimeReconcileInvokesPBPBridgeBestEffort(t *testing.T) {
	fixture := newRuntimeTestFixture(t)
	persistRuntimeFixtureConfig(t, fixture)
	client := newFakeRuntimeClient(fixture)
	deps := fixture.dependencies(nil, func(_ instanceclient.Config) (instanceRuntimeClient, error) { return client, nil })
	calls := 0
	deps.bridgePBPLogs = func(context.Context, instanceRuntimeConfig, instanceRuntimeClient, func() time.Time) error {
		calls++
		return errors.New("unsafe local source")
	}
	status, _, _ := invokeInstanceRuntime(t, []string{"reconcile", "--state-root", fixture.stateRoot}, deps)
	if status != exitOK || calls != 1 {
		t.Fatalf("status=%d bridge calls=%d", status, calls)
	}
}

type pbpRuntimeBridgeFixture struct {
	t         *testing.T
	home      string
	logs      string
	stateRoot string
	uid       uint32
	config    instanceRuntimeConfig
	now       time.Time
}

func newPBPRuntimeBridgeFixture(t *testing.T) pbpRuntimeBridgeFixture {
	t.Helper()
	base := t.TempDir()
	home := filepath.Join(base, "home")
	logs := filepath.Join(home, filepath.FromSlash(pbpRuntimeLogRelative))
	current := home
	for _, part := range append([]string{""}, strings.Split(pbpRuntimeLogRelative, "/")...) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
		if err := os.Chmod(current, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stateRoot := filepath.Join(base, "state")
	return pbpRuntimeBridgeFixture{
		t: t, home: home, logs: logs, stateRoot: stateRoot, uid: uint32(os.Getuid()),
		config: instanceRuntimeConfig{StateRoot: stateRoot, Instance: "pbp-01", Profile: "pbp"},
		now:    time.Unix(1_800_000_000, 0).UTC(),
	}
}

func (fixture pbpRuntimeBridgeFixture) writeLog(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fixture.logs, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(fixture.logs, name), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (fixture pbpRuntimeBridgeFixture) appendLog(t *testing.T, name, content string) {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(fixture.logs, name), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func (fixture pbpRuntimeBridgeFixture) run(t *testing.T, client *fakeRuntimeClient) {
	t.Helper()
	if err := fixture.runError(client); err != nil {
		t.Fatal(err)
	}
}

func (fixture pbpRuntimeBridgeFixture) runError(client *fakeRuntimeClient) error {
	return reportPBPRuntimeLogsFrom(context.Background(), fixture.config, client, func() time.Time {
		return fixture.now
	}, pbpRuntimeSource{home: fixture.home, uid: fixture.uid})
}

func flattenedPBPEvents(batches []serving.LogBatch) []string {
	var result []string
	for _, batch := range batches {
		for _, event := range batch.Events {
			value := event.Event
			if event.Code != "" {
				value += ":" + event.Code
			}
			result = append(result, value)
		}
	}
	return result
}
