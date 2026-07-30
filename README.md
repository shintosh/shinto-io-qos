# Shinto I/O QoS

Shinto I/O QoS is a small Linux cgroup v2 governor. It observes aggregate
Kubernetes workload writes and protects etcd latency through exact host-file
mounts.

The Go module uses only the standard library. Build and test it without module
network access:

```bash
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./...
CGO_ENABLED=0 GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  go build ./cmd/shinto-io-governor
```

The published image is `ghcr.io/shintosh/shinto-io-qos`. Consumers must select
an immutable digest. The runtime supports `observe`, `enforce`, and `clear`.
`observe` never writes cgroup controls. `enforce` requires one accepted
embedded policy. `clear` restores `max` and verifies readback.

The process uses only the five files defined in `contract/runtime.json`. It
opens no network socket and runs with a read-only root filesystem under the
consumer-owned sandbox.

Licensed under Apache-2.0. See `LICENSE`.
