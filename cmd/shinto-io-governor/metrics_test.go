package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetricsFilePublishesByAtomicRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.prom")
	if err := os.WriteFile(path, []byte("old 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err := writeMetricsFile(path, []byte("metric 1\n")); err != nil {
		t.Fatal(err)
	}
	previous, err := io.ReadAll(old)
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(previous) != "old 1\n" || string(current) != "metric 1\n" {
		t.Fatalf("previous=%q current=%q", previous, current)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %#o", info.Mode().Perm())
	}
}

func TestMetricsFileRejectsMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "metrics.prom")
	if err := writeMetricsFile(path, []byte("metric 1\n")); err == nil {
		t.Fatal("writeMetricsFile() succeeded")
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
			if publishes == 2 {
				cancel()
			}
			return nil
		},
		logger: &recordingRuntimeLogger{},
	}
	if err := run(ctx, deps); err != nil {
		t.Fatal(err)
	}
	if reconciles != 2 || samples != 1 || publishes != 2 {
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
			if publishes == 3 {
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
	publishes := 0
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
			publishes++
			if publishes == 1 {
				return nil
			}
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
