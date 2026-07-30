package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRuntimeContractMatchesSource(t *testing.T) {
	type runtimeContract struct {
		Command struct {
			Name       string   `json:"name"`
			Entrypoint string   `json:"entrypoint"`
			Modes      []string `json:"modes"`
		} `json:"command"`
		Files []struct {
			ContainerPath string `json:"container_path"`
		} `json:"files"`
		MetricsFamilyPrefix string `json:"metrics_family_prefix"`
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "contract", "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract runtimeContract
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{workloadMaxPath, workloadStatPath, etcdLatencyPath, etcdStatPath, metricsPath}
	gotPaths := make([]string, 0, len(contract.Files))
	for _, file := range contract.Files {
		gotPaths = append(gotPaths, file.ContainerPath)
	}
	if contract.Command.Name != "shinto-io-governor" || contract.Command.Entrypoint != "/shinto-io-governor" {
		t.Fatalf("command = %+v", contract.Command)
	}
	if !reflect.DeepEqual(contract.Command.Modes, []string{string(modeObserve), string(modeEnforce), string(modeClear)}) {
		t.Fatalf("modes = %v", contract.Command.Modes)
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("paths = %v, want %v", gotPaths, wantPaths)
	}
	if contract.MetricsFamilyPrefix != "shinto_io_governor_" {
		t.Fatalf("metrics prefix = %q", contract.MetricsFamilyPrefix)
	}
}

func TestParseIOStat(t *testing.T) {
	got, err := parseIOStat([]byte("259:0 rbytes=1 wbytes=20 rios=2 wios=3 dbytes=0 dios=0\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[device]ioCounters{{major: 259, minor: 0}: {readBytes: 1, writeBytes: 20, readIOs: 2, writeIOs: 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseIOStat() = %#v, want %#v", got, want)
	}
	for _, input := range []string{"259 rbytes=1", "x:y wbytes=1", "259:0 wbytes=nope", "259:0 future=1"} {
		if _, err := parseIOStat([]byte(input)); err == nil {
			t.Fatalf("parseIOStat(%q) succeeded", input)
		}
	}
}

func TestDiscoverDevice(t *testing.T) {
	etcd := []byte("259:0 rbytes=1 wbytes=2 rios=3 wios=4\n")
	for name, workload := range map[string][]byte{
		"early boot empty": nil,
		"same device":      []byte("259:0 rbytes=0 wbytes=1 rios=0 wios=1\n"),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := discoverDevice(etcd, workload)
			if err != nil {
				t.Fatal(err)
			}
			if got != (device{major: 259, minor: 0}) {
				t.Fatalf("device = %+v", got)
			}
		})
	}
	for name, fixture := range map[string]struct{ etcd, workload []byte }{
		"empty etcd":    {nil, nil},
		"multiple etcd": {[]byte("259:0 wbytes=1\n8:0 wbytes=1\n"), nil},
		"multiple work": {etcd, []byte("259:0 wbytes=1\n8:0 wbytes=1\n")},
		"different":     {etcd, []byte("8:0 wbytes=1\n")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := discoverDevice(fixture.etcd, fixture.workload); err == nil {
				t.Fatal("discoverDevice() succeeded")
			}
		})
	}
}

func TestValidateProfile(t *testing.T) {
	accepted := policyProfile{accepted: true, writeBPS: 100, writeIOPS: 200, targetMicros: 300, bounds: policyBounds{
		minWriteBPS: 100, maxWriteBPS: 100, minWriteIOPS: 200, maxWriteIOPS: 200, minTargetMicros: 300, maxTargetMicros: 300,
	}}
	if err := accepted.validate(); err != nil {
		t.Fatal(err)
	}
	for name, profile := range map[string]policyProfile{
		"unaccepted": {},
		"bps drift":  func() policyProfile { p := accepted; p.writeBPS++; return p }(),
		"iops drift": func() policyProfile { p := accepted; p.writeIOPS++; return p }(),
		"target drift": func() policyProfile {
			p := accepted
			p.targetMicros++
			return p
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := profile.validate(); err == nil {
				t.Fatal("validate() succeeded")
			}
		})
	}
}

type fakeFiles struct {
	values   map[string][]byte
	writes   []string
	failPath string
}

func (f *fakeFiles) read(path string) ([]byte, error) {
	value, ok := f.values[path]
	if !ok {
		return nil, errors.New("missing fake path")
	}
	return append([]byte(nil), value...), nil
}

func (f *fakeFiles) write(path string, value []byte) error {
	if path == f.failPath {
		return errors.New("injected write failure")
	}
	f.writes = append(f.writes, path+"="+string(value))
	f.values[path] = append([]byte(nil), value...)
	return nil
}

func testGovernor(files *fakeFiles) *governor {
	return &governor{
		paths:     controlPaths{workloadStat: "work.stat", workloadMax: "work.max", etcdStat: "etcd.stat", etcdLatency: "etcd.latency"},
		readFile:  files.read,
		writeFile: files.write,
	}
}

func acceptedTestProfile() policyProfile {
	return policyProfile{accepted: true, writeBPS: 104857600, writeIOPS: 2300, targetMicros: 5000, bounds: policyBounds{
		minWriteBPS: 104857600, maxWriteBPS: 104857600, minWriteIOPS: 2300, maxWriteIOPS: 2300, minTargetMicros: 5000, maxTargetMicros: 5000,
	}}
}

func TestReconcileObserveDoesNotWrite(t *testing.T) {
	files := &fakeFiles{values: map[string][]byte{"etcd.stat": []byte("259:0 wbytes=1\n"), "work.stat": nil}}
	state, err := testGovernor(files).reconcile(modeObserve, policyProfile{})
	if err != nil {
		t.Fatal(err)
	}
	if !state.topologyValid || len(files.writes) != 0 {
		t.Fatalf("state=%+v writes=%v", state, files.writes)
	}
}

func TestReconcileEnforceOrdersWritesAndReadsBack(t *testing.T) {
	files := &fakeFiles{values: map[string][]byte{
		"etcd.stat": []byte("259:0 wbytes=1\n"), "work.stat": []byte("259:0 wbytes=2\n"), "work.max": nil, "etcd.latency": nil,
	}}
	state, err := testGovernor(files).reconcile(modeEnforce, acceptedTestProfile())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"work.max=259:0 wbps=104857600 wiops=2300\n", "etcd.latency=259:0 target=5000\n"}
	if !reflect.DeepEqual(files.writes, want) || !state.policyComplete {
		t.Fatalf("writes=%q state=%+v", files.writes, state)
	}
}

func TestReconcileRejectsBeforeWrite(t *testing.T) {
	files := &fakeFiles{values: map[string][]byte{"etcd.stat": []byte("259:0 wbytes=1\n"), "work.stat": nil, "work.max": nil, "etcd.latency": nil}}
	if _, err := testGovernor(files).reconcile(modeEnforce, policyProfile{}); err == nil {
		t.Fatal("reconcile() succeeded")
	}
	if len(files.writes) != 0 {
		t.Fatalf("writes=%v", files.writes)
	}
}

func TestReconcileKeepsCapOnNestedFailure(t *testing.T) {
	files := &fakeFiles{values: map[string][]byte{
		"etcd.stat": []byte("259:0 wbytes=1\n"), "work.stat": nil, "work.max": nil, "etcd.latency": nil,
	}, failPath: "etcd.latency"}
	state, err := testGovernor(files).reconcile(modeEnforce, acceptedTestProfile())
	if err == nil {
		t.Fatal("reconcile() succeeded")
	}
	if len(files.writes) != 1 || !state.workloadApplied || state.policyComplete {
		t.Fatalf("writes=%v state=%+v", files.writes, state)
	}
}

func TestReconcileRetriesOnlyMissingNestedControl(t *testing.T) {
	files := &fakeFiles{values: map[string][]byte{
		"etcd.stat": []byte("259:0 wbytes=1\n"), "work.stat": nil, "work.max": nil, "etcd.latency": nil,
	}, failPath: "etcd.latency"}
	owner := testGovernor(files)
	if _, err := owner.reconcile(modeEnforce, acceptedTestProfile()); err == nil {
		t.Fatal("first reconcile succeeded")
	}
	files.failPath = ""
	state, err := owner.reconcile(modeEnforce, acceptedTestProfile())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"work.max=259:0 wbps=104857600 wiops=2300\n",
		"etcd.latency=259:0 target=5000\n",
	}
	if !reflect.DeepEqual(files.writes, want) || !state.policyComplete {
		t.Fatalf("writes=%q state=%+v", files.writes, state)
	}
}

func TestClearWritesMaxAndVerifies(t *testing.T) {
	files := &fakeFiles{values: map[string][]byte{
		"etcd.stat": []byte("259:0 wbytes=1\n"), "work.stat": nil, "work.max": nil, "etcd.latency": nil,
	}}
	state, err := testGovernor(files).reconcile(modeClear, policyProfile{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"work.max=259:0 wbps=max wiops=max\n", "etcd.latency=259:0 target=max\n"}
	if !reflect.DeepEqual(files.writes, want) || !state.policyComplete {
		t.Fatalf("writes=%q state=%+v", files.writes, state)
	}
}
