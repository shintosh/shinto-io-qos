package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

type recordingMetricsFile struct {
	calls      []string
	writeErr   error
	syncErr    error
	closeErr   error
	shortWrite bool
	written    string
}

func (f *recordingMetricsFile) Write(value []byte) (int, error) {
	f.calls = append(f.calls, "write")
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.shortWrite {
		return len(value) - 1, nil
	}
	f.written = string(value)
	return len(value), nil
}

func (f *recordingMetricsFile) Sync() error {
	f.calls = append(f.calls, "sync")
	return f.syncErr
}

func (f *recordingMetricsFile) Close() error {
	f.calls = append(f.calls, "close")
	return f.closeErr
}

func TestMetricsFileTruncatesWritesSyncsAndCloses(t *testing.T) {
	file := &recordingMetricsFile{}
	open := func(path string, flag int, perm fs.FileMode) (syncWriteCloser, error) {
		if path != "/metrics.prom" {
			t.Fatalf("path = %q", path)
		}
		wantFlag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		if flag != wantFlag || perm != 0o644 {
			t.Fatalf("flag=%d perm=%#o", flag, perm)
		}
		return file, nil
	}
	if err := writeMetricsFile("/metrics.prom", []byte("metric 1\n"), open); err != nil {
		t.Fatal(err)
	}
	if strings.Join(file.calls, ",") != "write,sync,close" {
		t.Fatalf("calls = %v", file.calls)
	}
	if file.written != "metric 1\n" {
		t.Fatalf("written = %q", file.written)
	}
}

func TestMetricsFileClosesAfterPartialFailure(t *testing.T) {
	for name, file := range map[string]*recordingMetricsFile{
		"write":       {writeErr: errors.New("write failed")},
		"short write": {shortWrite: true},
		"sync":        {syncErr: errors.New("sync failed")},
	} {
		t.Run(name, func(t *testing.T) {
			open := func(string, int, fs.FileMode) (syncWriteCloser, error) { return file, nil }
			if err := writeMetricsFile("/metrics.prom", []byte("metric 1\n"), open); err == nil {
				t.Fatal("writeMetricsFile() succeeded")
			}
			if file.calls[len(file.calls)-1] != "close" {
				t.Fatalf("calls = %v", file.calls)
			}
		})
	}
}

func TestMetricsRenderHasOnlyBoundedLabels(t *testing.T) {
	histograms := newSampleHistograms()
	histograms.observe(12_000_000, 700)
	snapshot := metricsSnapshot{
		buildRevision:    "0123456789abcdef",
		policyIdentity:   "observe-v1",
		mode:             modeObserve,
		reconcileSuccess: true,
		lastSuccess:      time.Unix(1234, 0),
		state: reconcileState{
			device: device{major: 259, minor: 0}, topologyValid: true,
		},
		histograms: histograms,
	}
	rendered := string(renderMetrics(snapshot))
	for _, required := range []string{
		"shinto_io_governor_build_info",
		"shinto_io_governor_mode",
		"shinto_io_governor_reconcile_success 1",
		"shinto_io_governor_last_success_timestamp_seconds 1234",
		"shinto_io_governor_device_info{major=\"259\",minor=\"0\"} 1",
		"shinto_io_governor_workload_write_bytes_per_second_bucket",
		"shinto_io_governor_workload_write_iops_bucket",
	} {
		if !strings.Contains(rendered, required) {
			t.Fatalf("metrics lack %q:\n%s", required, rendered)
		}
	}
	for _, forbidden := range []string{"workload=", "pod=", "daemon=", "path=", "error=", "device_model="} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("metrics contain forbidden label %q", forbidden)
		}
	}
}

func TestSamplerReadsBothStatsAndComputesOneSecondDelta(t *testing.T) {
	values := map[string][][]byte{
		"etcd": {
			[]byte("259:0 rbytes=0 wbytes=1 rios=0 wios=1\n"),
			[]byte("259:0 rbytes=0 wbytes=2 rios=0 wios=2\n"),
		},
		"work": {
			[]byte("259:0 rbytes=0 wbytes=100 rios=0 wios=10\n"),
			[]byte("259:0 rbytes=0 wbytes=300 rios=0 wios=14\n"),
		},
	}
	reads := map[string]int{}
	read := func(path string) ([]byte, error) {
		index := reads[path]
		reads[path]++
		return values[path][index], nil
	}
	sampler := newIOSampler("etcd", "work", read)
	first, err := sampler.sample(time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	second, err := sampler.sample(time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	if first.valid || second != (ioSample{writeBPS: 100, writeIOPS: 2, valid: true}) {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	if reads["etcd"] != 2 || reads["work"] != 2 {
		t.Fatalf("reads = %v", reads)
	}
}

type recordingRuntimeLogger struct {
	debug int
	error int
}

func (l *recordingRuntimeLogger) Debug(string, ...any) { l.debug++ }
func (l *recordingRuntimeLogger) Error(string, ...any) { l.error++ }

func TestRunReconcilesImmediatelySamplesPublishesAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sampleTicks := make(chan time.Time)
	publishTicks := make(chan time.Time)
	sampled := make(chan struct{})
	go func() {
		sampleTicks <- time.Unix(1, 0)
		<-sampled
		publishTicks <- time.Unix(30, 0)
	}()

	var reconciles, samples, publishes int
	deps := runDependencies{
		now:             func() time.Time { return time.Unix(0, 0) },
		sampleTicks:     sampleTicks,
		publishTicks:    publishTicks,
		samplingEnabled: true,
		reconcile: func() (reconcileState, error) {
			reconciles++
			return reconcileState{topologyValid: true}, nil
		},
		sample: func(time.Time) (ioSample, error) {
			samples++
			close(sampled)
			return ioSample{writeBPS: 10, writeIOPS: 2, valid: true}, nil
		},
		publish: func(reconcileState, bool, time.Time, sampleHistograms) error {
			publishes++
			cancel()
			return nil
		},
		logger: &recordingRuntimeLogger{},
	}
	if err := run(ctx, deps); err != nil {
		t.Fatal(err)
	}
	if reconciles != 2 || samples != 1 || publishes != 1 {
		t.Fatalf("reconciles=%d samples=%d publishes=%d", reconciles, samples, publishes)
	}
}

func TestRunLogsRetriesAtDebugAndExhaustionAtError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	publishTicks := make(chan time.Time, 2)
	publishTicks <- time.Unix(30, 0)
	publishTicks <- time.Unix(60, 0)
	logger := &recordingRuntimeLogger{}
	publishes := 0
	deps := runDependencies{
		now:             func() time.Time { return time.Unix(0, 0) },
		sampleTicks:     make(chan time.Time),
		publishTicks:    publishTicks,
		samplingEnabled: true,
		reconcile: func() (reconcileState, error) {
			return reconcileState{}, errors.New("injected reconcile failure")
		},
		sample: func(time.Time) (ioSample, error) { return ioSample{}, nil },
		publish: func(reconcileState, bool, time.Time, sampleHistograms) error {
			publishes++
			if publishes == 2 {
				cancel()
			}
			return nil
		},
		logger: logger,
	}
	if err := run(ctx, deps); err != nil {
		t.Fatal(err)
	}
	if logger.debug != 2 || logger.error != 1 {
		t.Fatalf("debug=%d error=%d", logger.debug, logger.error)
	}
}

func TestRunPreservesLastVerifiedPolicyAfterReconcileFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	publishTicks := make(chan time.Time, 1)
	publishTicks <- time.Unix(30, 0)
	reconciles := 0
	deps := runDependencies{
		now:             func() time.Time { return time.Unix(1, 0) },
		sampleTicks:     make(chan time.Time),
		publishTicks:    publishTicks,
		samplingEnabled: true,
		reconcile: func() (reconcileState, error) {
			reconciles++
			if reconciles == 1 {
				return reconcileState{
					device: device{major: 259}, topologyValid: true,
					workloadApplied: true, latencyApplied: true, policyComplete: true,
				}, nil
			}
			return reconcileState{}, errors.New("topology read failed")
		},
		sample: func(time.Time) (ioSample, error) { return ioSample{}, nil },
		publish: func(state reconcileState, success bool, _ time.Time, _ sampleHistograms) error {
			if success || state.topologyValid || !state.policyComplete || state.device.major != 259 {
				t.Fatalf("state=%+v success=%v", state, success)
			}
			cancel()
			return nil
		},
		logger: &recordingRuntimeLogger{},
	}
	if err := run(ctx, deps); err != nil {
		t.Fatal(err)
	}
}

func TestRunCommandRejectsUnknownModeAndUnacceptedEnforcement(t *testing.T) {
	for name, args := range map[string][]string{
		"unknown":    {"--mode=unknown"},
		"unaccepted": {"--mode=enforce"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := runCommand(args); err == nil {
				t.Fatal("runCommand() succeeded")
			}
		})
	}
}
