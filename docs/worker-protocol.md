# Capability-only worker protocol

The Phase 0 worker endpoint is a narrow subprocess handshake, not an execution backend.
It answers one question—what prerequisites are visible on this host?—and its v1 schemas
cannot request compilation, verifier loading, program execution, a host path, an
environment variable, or arbitrary command arguments.

Every execution and official-eligibility field in `bpe.worker-capabilities.v1` is a literal
`false`. A future evaluator must introduce a new versioned operation and capability schema;
v1 cannot be extended in place to claim execution.

## Request and response

The only valid request has exactly three fields:

```json
{"method":"capabilities","request_id":"probe-001","schema_version":"bpe.worker-request.v1"}
```

Success and error responses form a closed union discriminated by `status`. Every
protocol-level response to a request that passes transport admission binds both its
validated `request_id` and the SHA-256 digest of the canonical request value. Transport
rejections use null correlation fields because the input was not admitted to canonical
protocol processing; this includes inputs rejected by the structural-complexity guard.

Hosts must call `validate_worker_subprocess_result` against the outstanding request and the
complete binary `subprocess.CompletedProcess`. The acceptance boundary checks the process
exit, stderr, byte limit, exactly-one-frame rule, strict JSON, canonical wire bytes,
correlation, and success discriminator. Parsed-object validation alone is insufficient: it
can erase duplicate keys, extra frames, or noncanonical representations, and a stale but
well-formed response must be treated as infrastructure failure.

The published contracts are available from an installed wheel:

```bash
bpe schema show worker-capabilities-v1.json
bpe schema show worker-request-v1.json
bpe schema show worker-response-v1.json
```

## Framing and lifecycle

`bpe-worker` uses binary standard input and output and handles at most one request per
process:

- input is strict UTF-8 JSON followed by exactly one LF byte;
- CRLF, a blank line, or EOF before LF is an invalid frame;
- the JSON payload limit is 16,384 bytes, excluding LF;
- duplicate keys, nonfinite or overflowing numbers, excess nesting, and excess JSON nodes
  are rejected before dispatch;
- output is one canonical compact UTF-8 JSON value followed by LF and is capped at 32,768
  bytes;
- an empty input stream exits successfully without output; and
- after one response the process exits, so a second supplied frame is never dispatched.

Stdout contains protocol bytes only. Rejected input and internal exception text are never
reflected. The endpoint currently emits no stderr output; a host must still bound and
capture stderr and reject any unexpected content.

The Phase 0 helper validates captured bytes but does not itself launch or supervise the
process. Callers must impose a hard deadline and cap stdout and stderr while reading, not
only after capture. This becomes mandatory before any hostile or execution-capable worker
is introduced.

The process exit contract is:

| Exit | Meaning |
|---:|---|
| 0 | clean empty EOF, or one framed request received a typed response |
| 2 | invalid encoding, framing, size, or strict JSON; one uncorrelated error may be emitted |
| 3 | internal handling or serialization failure |
| 4 | response I/O failure, including a closed pipe |

A typed error inside an exit-0 response is not success. In particular,
`capability_probe_failed`, `invalid_request`, and `unsupported_method` remain failures for
the caller. Nonzero exit, timeout, missing output, malformed output, correlation mismatch,
extra frames, unexpected stdout bytes, or unexpected stderr all map to infrastructure
failure—never to candidate failure or benchmark success.

## Error codes

The v1 error vocabulary is fixed and messages are single-line, bounded, and
non-reflective:

- `invalid_encoding`
- `invalid_frame`
- `invalid_json`
- `frame_too_large`
- `invalid_request`
- `unsupported_method`
- `capability_probe_failed`
- `internal_error`

Unknown codes invalidate the entire response.

## Trust boundary

This subprocess protocol is portable contract scaffolding. It does not authenticate the
worker, isolate it, prove that reported files were measured, or bind a fresh microVM
snapshot. Even on Linux with Clang, bpftool, and BTF present, the response says only that
host prerequisites were observed; compilation, loading, and official eligibility remain
false.

The Phase 1B.1 [cgroup-v2 empty-leaf qualification](cgroup-qualification.md) is not a new
worker method and cannot be tunneled through this request. Its unsigned post-removal report
contains no process, candidate, or launch authority; it does not upgrade a capability
response into an execution-capable protocol.

The authoritative path will use a separately versioned request over a bounded vsock
channel to a disposable pinned microVM. Candidate bytes and grader inputs will travel as a
content-addressed closed bundle beneath a trusted artifact root—never as an arbitrary host
path. That future protocol also needs a host client that enforces deadlines, response
correlation, output limits, replay construction, snapshot identity, and authenticated
attestation.
