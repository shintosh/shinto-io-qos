package main

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"fmt"
)

var (
	writeBPSBuckets = []uint64{
		1 << 20,
		5 << 20,
		10 << 20,
		25 << 20,
		50 << 20,
		100 << 20,
		200 << 20,
		400 << 20,
	}
	writeIOPSBuckets = []uint64{100, 500, 1000, 2000, 4000, 8000, 16000}
)

type syncWriteCloser interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

type metricsFileOpener func(string, int, fs.FileMode) (syncWriteCloser, error)

func writeMetricsFile(path string, value []byte, open metricsFileOpener) error {
	file, err := open(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open metrics file: %w", err)
	}
	written, err := file.Write(value)
	if err == nil && written != len(value) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("write metrics file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync metrics file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close metrics file: %w", err)
	}
	return nil
}

type fixedHistogram struct {
	bounds []uint64
	counts []uint64
	count  uint64
	sum    uint64
}

func newFixedHistogram(bounds []uint64) fixedHistogram {
	return fixedHistogram{
		bounds: append([]uint64(nil), bounds...),
		counts: make([]uint64, len(bounds)),
	}
}

func (h *fixedHistogram) observe(value uint64) {
	for index, bound := range h.bounds {
		if value <= bound {
			h.counts[index]++
		}
	}
	h.count++
	h.sum += value
}

type sampleHistograms struct {
	writeBPS  fixedHistogram
	writeIOPS fixedHistogram
}

func newSampleHistograms() sampleHistograms {
	return sampleHistograms{
		writeBPS:  newFixedHistogram(writeBPSBuckets),
		writeIOPS: newFixedHistogram(writeIOPSBuckets),
	}
}

func (h *sampleHistograms) observe(writeBPS, writeIOPS uint64) {
	h.writeBPS.observe(writeBPS)
	h.writeIOPS.observe(writeIOPS)
}

type ioSample struct {
	writeBPS  uint64
	writeIOPS uint64
	valid     bool
}

type ioSampler struct {
	etcdStat     string
	workloadStat string
	readFile     func(string) ([]byte, error)
	previous     ioCounters
	previousAt   time.Time
	initialized  bool
}

func newIOSampler(etcdStat, workloadStat string, readFile func(string) ([]byte, error)) *ioSampler {
	return &ioSampler{etcdStat: etcdStat, workloadStat: workloadStat, readFile: readFile}
}

func (s *ioSampler) sample(at time.Time) (ioSample, error) {
	etcdData, err := s.readFile(s.etcdStat)
	if err != nil {
		return ioSample{}, fmt.Errorf("sample etcd io.stat: %w", err)
	}
	workloadData, err := s.readFile(s.workloadStat)
	if err != nil {
		return ioSample{}, fmt.Errorf("sample workload io.stat: %w", err)
	}
	dev, err := discoverDevice(etcdData, workloadData)
	if err != nil {
		return ioSample{}, err
	}
	workload, err := parseIOStat(workloadData)
	if err != nil {
		return ioSample{}, fmt.Errorf("parse sampled workload io.stat: %w", err)
	}
	current := workload[dev]
	if !s.initialized {
		s.previous = current
		s.previousAt = at
		s.initialized = true
		return ioSample{}, nil
	}
	elapsed := at.Sub(s.previousAt)
	if elapsed <= 0 {
		return ioSample{}, fmt.Errorf("sample timestamp did not advance")
	}
	result := ioSample{}
	if current.writeBytes >= s.previous.writeBytes {
		result.writeBPS = (current.writeBytes - s.previous.writeBytes) * uint64(time.Second) / uint64(elapsed)
	}
	if current.writeIOs >= s.previous.writeIOs {
		result.writeIOPS = (current.writeIOs - s.previous.writeIOs) * uint64(time.Second) / uint64(elapsed)
	}
	result.valid = true
	s.previous = current
	s.previousAt = at
	return result, nil
}

type metricsSnapshot struct {
	buildRevision     string
	policyIdentity    string
	mode              mode
	reconcileSuccess  bool
	lastSuccess       time.Time
	state             reconcileState
	desired           policyProfile
	observedWriteBPS  uint64
	observedWriteIOPS uint64
	observedTarget    uint64
	histograms        sampleHistograms
}

func renderMetrics(snapshot metricsSnapshot) []byte {
	var output bytes.Buffer
	writeMetric(&output, "shinto_io_governor_build_info", map[string]string{
		"policy": snapshot.policyIdentity, "revision": snapshot.buildRevision,
	}, 1)
	for _, candidate := range []mode{modeObserve, modeEnforce, modeClear} {
		value := uint64(0)
		if snapshot.mode == candidate {
			value = 1
		}
		writeMetric(&output, "shinto_io_governor_mode", map[string]string{"mode": string(candidate)}, value)
	}
	writeBooleanMetric(&output, "shinto_io_governor_reconcile_success", snapshot.reconcileSuccess)
	lastSuccess := int64(0)
	if !snapshot.lastSuccess.IsZero() {
		lastSuccess = snapshot.lastSuccess.Unix()
	}
	writeSignedMetric(&output, "shinto_io_governor_last_success_timestamp_seconds", lastSuccess)
	writeBooleanMetric(&output, "shinto_io_governor_topology_valid", snapshot.state.topologyValid)
	writeBooleanMetric(&output, "shinto_io_governor_policy_complete", snapshot.state.policyComplete)
	if snapshot.state.topologyValid {
		writeMetric(&output, "shinto_io_governor_device_info", map[string]string{
			"major": strconv.FormatUint(uint64(snapshot.state.device.major), 10),
			"minor": strconv.FormatUint(uint64(snapshot.state.device.minor), 10),
		}, 1)
	}
	writeMetric(&output, "shinto_io_governor_desired_write_bytes_per_second", nil, snapshot.desired.writeBPS)
	writeMetric(&output, "shinto_io_governor_observed_write_bytes_per_second", nil, snapshot.observedWriteBPS)
	writeMetric(&output, "shinto_io_governor_desired_write_iops", nil, snapshot.desired.writeIOPS)
	writeMetric(&output, "shinto_io_governor_observed_write_iops", nil, snapshot.observedWriteIOPS)
	writeMetric(&output, "shinto_io_governor_desired_latency_target_microseconds", nil, snapshot.desired.targetMicros)
	writeMetric(&output, "shinto_io_governor_observed_latency_target_microseconds", nil, snapshot.observedTarget)
	writeHistogram(&output, "shinto_io_governor_workload_write_bytes_per_second", snapshot.histograms.writeBPS)
	writeHistogram(&output, "shinto_io_governor_workload_write_iops", snapshot.histograms.writeIOPS)
	return output.Bytes()
}

func writeBooleanMetric(output *bytes.Buffer, name string, value bool) {
	numeric := uint64(0)
	if value {
		numeric = 1
	}
	writeMetric(output, name, nil, numeric)
}

func writeSignedMetric(output *bytes.Buffer, name string, value int64) {
	output.WriteString(name)
	output.WriteByte(' ')
	output.WriteString(strconv.FormatInt(value, 10))
	output.WriteByte('\n')
}

func writeMetric(output *bytes.Buffer, name string, labels map[string]string, value uint64) {
	output.WriteString(name)
	writeLabels(output, labels)
	output.WriteByte(' ')
	output.WriteString(strconv.FormatUint(value, 10))
	output.WriteByte('\n')
}

func writeLabels(output *bytes.Buffer, labels map[string]string) {
	if len(labels) == 0 {
		return
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	output.WriteByte('{')
	for index, key := range keys {
		if index > 0 {
			output.WriteByte(',')
		}
		output.WriteString(key)
		output.WriteString("=\"")
		output.WriteString(escapeLabel(labels[key]))
		output.WriteByte('"')
	}
	output.WriteByte('}')
}

func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, "\"", "\\\"")
}

func writeHistogram(output *bytes.Buffer, name string, histogram fixedHistogram) {
	for index, bound := range histogram.bounds {
		writeMetric(output, name+"_bucket", map[string]string{"le": strconv.FormatUint(bound, 10)}, histogram.counts[index])
	}
	writeMetric(output, name+"_bucket", map[string]string{"le": "+Inf"}, histogram.count)
	writeMetric(output, name+"_count", nil, histogram.count)
	writeMetric(output, name+"_sum", nil, histogram.sum)
}
