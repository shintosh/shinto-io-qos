package main

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"

	"fmt"
)

type device struct {
	major uint32
	minor uint32
}

func (d device) String() string {
	return strconv.FormatUint(uint64(d.major), 10) + ":" + strconv.FormatUint(uint64(d.minor), 10)
}

type ioCounters struct {
	readBytes  uint64
	writeBytes uint64
	readIOs    uint64
	writeIOs   uint64
}

func (c ioCounters) active() bool {
	return c.readBytes != 0 || c.writeBytes != 0 || c.readIOs != 0 || c.writeIOs != 0
}

func parseIOStat(data []byte) (map[device]ioCounters, error) {
	result := make(map[device]ioCounters)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		dev, err := parseDevice(fields[0])
		if err != nil {
			return nil, err
		}
		if _, exists := result[dev]; exists {
			return nil, fmt.Errorf("duplicate I/O device %s", dev.String())
		}
		var counters ioCounters
		for _, field := range fields[1:] {
			key, raw, ok := strings.Cut(field, "=")
			if !ok || key == "" || raw == "" {
				return nil, fmt.Errorf("invalid io.stat field %q", field)
			}
			value, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse io.stat field %q: %w", field, err)
			}
			switch key {
			case "rbytes":
				counters.readBytes = value
			case "wbytes":
				counters.writeBytes = value
			case "rios":
				counters.readIOs = value
			case "wios":
				counters.writeIOs = value
			case "dbytes", "dios":
			default:
				return nil, fmt.Errorf("unsupported io.stat field %q", key)
			}
		}
		result[dev] = counters
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan io.stat: %w", err)
	}
	return result, nil
}

func parseDevice(value string) (device, error) {
	major, minor, ok := strings.Cut(value, ":")
	if !ok || major == "" || minor == "" {
		return device{}, fmt.Errorf("invalid I/O device %q", value)
	}
	majorValue, err := strconv.ParseUint(major, 10, 32)
	if err != nil {
		return device{}, fmt.Errorf("parse I/O device major %q: %w", major, err)
	}
	minorValue, err := strconv.ParseUint(minor, 10, 32)
	if err != nil {
		return device{}, fmt.Errorf("parse I/O device minor %q: %w", minor, err)
	}
	return device{major: uint32(majorValue), minor: uint32(minorValue)}, nil
}

func discoverDevice(etcdData, workloadData []byte) (device, error) {
	etcd, err := parseIOStat(etcdData)
	if err != nil {
		return device{}, fmt.Errorf("parse etcd io.stat: %w", err)
	}
	workload, err := parseIOStat(workloadData)
	if err != nil {
		return device{}, fmt.Errorf("parse workload io.stat: %w", err)
	}
	etcdActive := activeDevices(etcd)
	if len(etcdActive) != 1 {
		return device{}, fmt.Errorf("etcd must have exactly one active I/O device, got %d", len(etcdActive))
	}
	workloadActive := activeDevices(workload)
	if len(workloadActive) > 1 {
		return device{}, fmt.Errorf("workload must have at most one active I/O device, got %d", len(workloadActive))
	}
	if len(workloadActive) == 1 && workloadActive[0] != etcdActive[0] {
		return device{}, fmt.Errorf("workload and etcd I/O devices differ")
	}
	return etcdActive[0], nil
}

func activeDevices(values map[device]ioCounters) []device {
	result := make([]device, 0, len(values))
	for dev, counters := range values {
		if counters.active() {
			result = append(result, dev)
		}
	}
	return result
}

type policyBounds struct {
	minWriteBPS     uint64
	maxWriteBPS     uint64
	minWriteIOPS    uint64
	maxWriteIOPS    uint64
	minTargetMicros uint64
	maxTargetMicros uint64
}

type policyProfile struct {
	accepted     bool
	writeBPS     uint64
	writeIOPS    uint64
	targetMicros uint64
	bounds       policyBounds
}

func (p policyProfile) validate() error {
	if !p.accepted {
		return fmt.Errorf("enforcement requires an accepted policy profile")
	}
	if p.writeBPS < p.bounds.minWriteBPS || p.writeBPS > p.bounds.maxWriteBPS {
		return fmt.Errorf("write BPS is outside compiled policy bounds")
	}
	if p.writeIOPS < p.bounds.minWriteIOPS || p.writeIOPS > p.bounds.maxWriteIOPS {
		return fmt.Errorf("write IOPS is outside compiled policy bounds")
	}
	if p.targetMicros < p.bounds.minTargetMicros || p.targetMicros > p.bounds.maxTargetMicros {
		return fmt.Errorf("latency target is outside compiled policy bounds")
	}
	return nil
}

type mode string

const (
	modeObserve mode = "observe"
	modeEnforce mode = "enforce"
	modeClear   mode = "clear"
)

type controlPaths struct {
	workloadStat string
	workloadMax  string
	etcdStat     string
	etcdLatency  string
}

type reconcileState struct {
	device          device
	topologyValid   bool
	workloadApplied bool
	latencyApplied  bool
	policyComplete  bool
}

type governor struct {
	paths     controlPaths
	readFile  func(string) ([]byte, error)
	writeFile func(string, []byte) error
	pending   *pendingControl
}

type pendingControl struct {
	device    device
	writeBPS  string
	writeIOPS string
	target    string
}

func (g *governor) reconcile(selected mode, profile policyProfile) (reconcileState, error) {
	if selected != modeObserve && selected != modeEnforce && selected != modeClear {
		return reconcileState{}, fmt.Errorf("unsupported governor mode %q", selected)
	}
	etcdData, err := g.readFile(g.paths.etcdStat)
	if err != nil {
		return reconcileState{}, fmt.Errorf("read etcd io.stat: %w", err)
	}
	workloadData, err := g.readFile(g.paths.workloadStat)
	if err != nil {
		return reconcileState{}, fmt.Errorf("read workload io.stat: %w", err)
	}
	dev, err := discoverDevice(etcdData, workloadData)
	if err != nil {
		return reconcileState{}, err
	}
	state := reconcileState{device: dev, topologyValid: true}
	if selected == modeObserve {
		return state, nil
	}
	if selected == modeEnforce {
		if err := profile.validate(); err != nil {
			return state, err
		}
		return g.apply(state, strconv.FormatUint(profile.writeBPS, 10), strconv.FormatUint(profile.writeIOPS, 10), strconv.FormatUint(profile.targetMicros, 10))
	}
	return g.apply(state, "max", "max", "max")
}

func (g *governor) apply(state reconcileState, writeBPS, writeIOPS, target string) (reconcileState, error) {
	desired := pendingControl{device: state.device, writeBPS: writeBPS, writeIOPS: writeIOPS, target: target}
	if g.pending != nil && *g.pending == desired {
		state.workloadApplied = true
		return g.applyLatency(state, desired)
	}
	g.pending = nil
	workload := state.device.String() + " wbps=" + writeBPS + " wiops=" + writeIOPS + "\n"
	if err := g.writeFile(g.paths.workloadMax, []byte(workload)); err != nil {
		return state, fmt.Errorf("write workload policy: %w", err)
	}
	readback, err := g.readFile(g.paths.workloadMax)
	if err != nil {
		return state, fmt.Errorf("read workload policy: %w", err)
	}
	if err := verifyControl(readback, state.device, map[string]string{"wbps": writeBPS, "wiops": writeIOPS}); err != nil {
		return state, fmt.Errorf("verify workload policy: %w", err)
	}
	state.workloadApplied = true
	g.pending = &desired
	return g.applyLatency(state, desired)
}

func (g *governor) applyLatency(state reconcileState, desired pendingControl) (reconcileState, error) {
	latency := state.device.String() + " target=" + desired.target + "\n"
	if err := g.writeFile(g.paths.etcdLatency, []byte(latency)); err != nil {
		return state, fmt.Errorf("write etcd latency policy: %w", err)
	}
	readback, err := g.readFile(g.paths.etcdLatency)
	if err != nil {
		return state, fmt.Errorf("read etcd latency policy: %w", err)
	}
	if err := verifyControl(readback, state.device, map[string]string{"target": desired.target}); err != nil {
		return state, fmt.Errorf("verify etcd latency policy: %w", err)
	}
	state.latencyApplied = true
	state.policyComplete = true
	g.pending = nil
	return state, nil
}

func verifyControl(data []byte, expectedDevice device, expected map[string]string) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		dev, err := parseDevice(fields[0])
		if err != nil {
			return err
		}
		if dev != expectedDevice {
			continue
		}
		observed := make(map[string]string, len(fields)-1)
		for _, field := range fields[1:] {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				return fmt.Errorf("invalid control field %q", field)
			}
			observed[key] = value
		}
		for key, value := range expected {
			if observed[key] != value {
				return fmt.Errorf("control %s readback is %q, want %q", key, observed[key], value)
			}
		}
		return nil
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan control readback: %w", err)
	}
	return fmt.Errorf("control readback lacks device %s", expectedDevice.String())
}
