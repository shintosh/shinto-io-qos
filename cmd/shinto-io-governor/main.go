package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fmt"
)

const (
	workloadStatPath = "/host-cgroup/kubepods/io.stat"
	workloadMaxPath  = "/host-cgroup/kubepods/io.max"
	etcdStatPath     = "/host-cgroup/podruntime/etcd/io.stat"
	etcdLatencyPath  = "/host-cgroup/podruntime/etcd/io.latency"
	metricsPath      = "/var/run/shinto-io-governor.prom"

	reconcileFailureLimit = 3
)

var (
	buildRevision  = "dev"
	policyIdentity = "observe-unaccepted-v1"
	embeddedPolicy = policyProfile{}
)

type runtimeLogger interface {
	Debug(string, ...any)
	Error(string, ...any)
}

type slogRuntimeLogger struct{}

func (slogRuntimeLogger) Debug(message string, args ...any) { slog.Debug(message, args...) }
func (slogRuntimeLogger) Error(message string, args ...any) { slog.Error(message, args...) }

type runDependencies struct {
	now             func() time.Time
	sampleTicks     <-chan time.Time
	publishTicks    <-chan time.Time
	samplingEnabled bool
	reconcile       func() (reconcileState, error)
	sample          func(time.Time) (ioSample, error)
	publish         func(reconcileState, bool, time.Time, sampleHistograms) error
	logger          runtimeLogger
}

func (d runDependencies) validate() error {
	if d.now == nil || d.sampleTicks == nil || d.publishTicks == nil || d.reconcile == nil || d.sample == nil || d.publish == nil || d.logger == nil {
		return fmt.Errorf("governor runtime dependencies are incomplete")
	}
	return nil
}

func run(ctx context.Context, deps runDependencies) error {
	if err := deps.validate(); err != nil {
		return err
	}
	histograms := newSampleHistograms()
	var state reconcileState
	var lastSuccess time.Time
	reconcileSuccess := false
	consecutiveFailures := 0
	publishFailures := 0

	reconcileNow := func() {
		observed, err := deps.reconcile()
		if err == nil {
			state = observed
			reconcileSuccess = true
			lastSuccess = deps.now()
			consecutiveFailures = 0
			return
		}
		if state.workloadApplied {
			observed.workloadApplied = true
		}
		if state.latencyApplied {
			observed.latencyApplied = true
		}
		if observed.device == (device{}) && (state.topologyValid || state.workloadApplied || state.latencyApplied) {
			observed.device = state.device
		}
		observed.policyComplete = observed.workloadApplied && observed.latencyApplied
		state = observed
		reconcileSuccess = false
		consecutiveFailures++
		if consecutiveFailures < reconcileFailureLimit {
			deps.logger.Debug("I/O policy reconcile will retry", "attempt", consecutiveFailures, "error", err)
			return
		}
		deps.logger.Error("I/O policy reconcile retries exhausted", "attempts", consecutiveFailures, "error", err)
	}

	reconcileNow()
	for {
		select {
		case <-ctx.Done():
			return nil
		case tick, ok := <-deps.sampleTicks:
			if !ok {
				return fmt.Errorf("governor sample ticker closed")
			}
			if !deps.samplingEnabled {
				continue
			}
			sample, err := deps.sample(tick)
			if err != nil {
				deps.logger.Debug("I/O sample will retry", "error", err)
				continue
			}
			if sample.valid {
				histograms.observe(sample.writeBPS, sample.writeIOPS)
			}
		case _, ok := <-deps.publishTicks:
			if !ok {
				return fmt.Errorf("governor publish ticker closed")
			}
			reconcileNow()
			if err := deps.publish(state, reconcileSuccess, lastSuccess, histograms); err != nil {
				publishFailures++
				if publishFailures < reconcileFailureLimit {
					deps.logger.Debug("metrics publish will retry", "attempt", publishFailures, "error", err)
				} else {
					deps.logger.Error("metrics publish retries exhausted", "attempts", publishFailures, "error", err)
				}
				continue
			}
			publishFailures = 0
			histograms = newSampleHistograms()
		}
	}
}

func main() {
	if err := runCommand(os.Args[1:]); err != nil {
		slog.Error("shinto-io-governor stopped", "error", err)
		os.Exit(1)
	}
}

func runCommand(args []string) error {
	flags := flag.NewFlagSet("shinto-io-governor", flag.ContinueOnError)
	selectedValue := flags.String("mode", string(modeObserve), "observe, enforce, or clear")
	if err := flags.Parse(args); err != nil {
		return err
	}
	selected := mode(*selectedValue)
	if selected != modeObserve && selected != modeEnforce && selected != modeClear {
		return fmt.Errorf("unsupported governor mode %q", selected)
	}
	if selected == modeEnforce {
		if err := embeddedPolicy.validate(); err != nil {
			return fmt.Errorf("validate embedded policy: %w", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	paths := controlPaths{
		workloadStat: workloadStatPath,
		workloadMax:  workloadMaxPath,
		etcdStat:     etcdStatPath,
		etcdLatency:  etcdLatencyPath,
	}
	owner := &governor{
		paths: paths, readFile: os.ReadFile,
		writeFile: func(path string, value []byte) error { return os.WriteFile(path, value, 0o644) },
	}
	sampler := newIOSampler(paths.etcdStat, paths.workloadStat, os.ReadFile)
	sampleTicker := time.NewTicker(time.Second)
	defer sampleTicker.Stop()
	publishTicker := time.NewTicker(30 * time.Second)
	defer publishTicker.Stop()

	open := func(path string, flag int, perm os.FileMode) (syncWriteCloser, error) {
		return os.OpenFile(path, flag, perm)
	}
	publish := func(state reconcileState, success bool, lastSuccess time.Time, histograms sampleHistograms) error {
		snapshot := metricsSnapshot{
			buildRevision: buildRevision, policyIdentity: policyIdentity, mode: selected,
			reconcileSuccess: success, lastSuccess: lastSuccess, state: state,
			desired: embeddedPolicy, histograms: histograms,
		}
		if selected == modeEnforce {
			if state.workloadApplied {
				snapshot.observedWriteBPS = embeddedPolicy.writeBPS
				snapshot.observedWriteIOPS = embeddedPolicy.writeIOPS
			}
			if state.latencyApplied {
				snapshot.observedTarget = embeddedPolicy.targetMicros
			}
		}
		return writeMetricsFile(metricsPath, renderMetrics(snapshot), open)
	}

	slog.Info("shinto-io-governor started", "mode", selected, "policy", policyIdentity)
	err := run(ctx, runDependencies{
		now: time.Now, sampleTicks: sampleTicker.C, publishTicks: publishTicker.C,
		samplingEnabled: selected != modeClear,
		reconcile:       func() (reconcileState, error) { return owner.reconcile(selected, embeddedPolicy) },
		sample:          sampler.sample, publish: publish, logger: slogRuntimeLogger{},
	})
	slog.Info("shinto-io-governor stopped")
	return err
}
