# BPE

BPE is the grading and execution foundation for training small language models to repair
and generate eBPF programs that the Linux kernel can prove safe.

The public repository is a reviewed source projection. It intentionally omits active
evaluator-private grader artifacts and the internal test/CI projection; the evaluator's
Git history is never publication-safe merely because its current worktree is filtered. See
[the publication boundary](docs/publication.md).

The project's primary claim is deliberately strict: a task is solved only when the
candidate compiles with the fixed toolchain, passes object-policy checks, loads through
the real verifier on the pinned kernel, preserves the required behavior on every hidden
case, and satisfies every anti-hack obligation. Verifier acceptance by itself earns no
benchmark credit.

This repository currently contains the **Phase 0 grading contract**, the non-executing
**Phase 1A dispatch primitive**, the non-executing **Phase 1B.0 Linux ingress boundary**,
the non-executing **Phase 1B.1 cgroup-v2 empty-leaf qualification boundary**, and the
pure-Python, non-launching **Phase 1B.2a inert-fixture intent admission** and
**Phase 1B.2b-0 launch-attempt consumption boundaries**:

- strict, versioned task, suite, experiment, exact-check scoring-contract, evidence,
  environment, grade, policy, replay, and attestation-registry schemas;
- a pure scorer that separates benchmark success from RL reward shaping;
- content-addressed replay bundles that can be integrity-checked, externally anchored,
  and rescored;
- pass@k aggregation, uncertainty intervals, root-cause slices, and failure-stage reports;
- public/private task projections and static leakage/admission linting;
- a provisional, fail-closed dynamic-admission receipt for complete repair-task evidence
  matrices;
- a provisional grader-qualification gate over byte-sealed, identity-disjoint
  calibration/validation tasks, exact witness/control kill matrices, repeated prepared
  jobs, and predeclared reward rankings;
- a frozen, closed-tree corpus manifest and blocking static contamination audit;
- a typed, bounded, one-frame capability-only worker subprocess protocol;
- prepared, content-addressed evaluation job bundles with exact identity binding and a
  descriptor-relative closed-tree loader;
- typed microVM/resource profiles plus short-lived Ed25519 dispatch authorizations that
  bind an exact prepared job and have a durable, atomic one-shot claim ledger;
- Linux x86-64 `openat2` ingress that proves an exact committed claim, securely opens a
  digest-addressed job, and atomically publishes a verified worker-owned copy without
  executing it;
- Linux x86-64 cgroup-v2 qualification that configures, exactly reads back, kills while
  empty, and removes one leaf beneath a pre-opened exclusive systemd delegation, without
  creating a process or authorizing launch;
- short-lived Ed25519 intents that bind one future fixed launcher artifact and built-in
  inert-fixture protocol to one worker and configured physical claim ledger, with a durable
  ledger-local one-shot receipt that cannot launch anything;
- a distinct, explicitly provisioned launch-attempt ledger that reauthenticates the
  original intent and exact committed claim, atomically consumes the sole attempt, and
  emits only terminal `launch_attempt_consumed_not_started` evidence;
- durable subject reservations in both fixture ledgers, so nonce/receipt construction or
  identity collisions leave a subject-specific terminal tombstone instead of reopening a
  retry path;
- a separately compiled Linux x86-64 static-PIE launcher with a fixed seccomp filter,
  built-in no-exec child, exact `clone3`/pidfd/cgroup state machine, and cross-language
  bounded result parser; the artifact is build-audited but not yet callable from Python;
- a typed, deterministic XDP differential oracle for return values, packet/context bytes,
  maps, ordered events, counters, and first-divergence evidence;
- a cross-platform worker capability probe that refuses to claim verifier support on macOS;
- an adversarial missing-null-check smoke task; and
- unit, contract, and tamper-detection tests.

Privileged verifier execution is intentionally not faked on macOS. Signed dispatch, Linux
ingress, cgroup qualification, inert-fixture admission, and launch-attempt consumption still
return `execution_started: false` and `authoritative: false`. The remaining Phase 1B.2b-1
work is immutable artifact preflight, atomic Python launch orchestration, and privileged
Linux qualification of the fixed
`clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)` supervisor. That is followed by a pinned Linux
XDP compiler and disposable microVM worker. See [the
grading design](docs/grading.md), [provisional admission
contract](docs/admission.md), [contamination gate](docs/contamination.md), [environment
contract](docs/environment.md), [grader qualification](docs/grader-qualification.md), [typed
XDP oracle](docs/oracle.md), [prepared evaluation jobs](docs/evaluation-jobs.md), [worker
protocol](docs/worker-protocol.md), [signed dispatch admission](docs/dispatch-admission.md),
[Linux claimed-job ingress](docs/linux-ingress.md), [repair
taxonomy](docs/root-cause-taxonomy.md), [cgroup-v2 empty-leaf
qualification](docs/cgroup-qualification.md), [inert-fixture intent
admission](docs/inert-fixture-admission.md), and [roadmap](docs/roadmap.md).

## Quick start

```bash
uv sync --extra dev
uv run bpe task admission --help
uv run bpe corpus --help
uv run bpe schema show worker-response-v1.json
uv run bpe schema show evaluation-job-v1.json
uv run bpe schema show signed-dispatch-authorization-v1.json
uv run bpe schema show linux-job-ingress-policy-v1.json
uv run bpe schema show linux-cgroup-v2-qualification-policy-v1.json
uv run bpe schema show linux-cgroup-v2-qualification-report-v1.json
uv run bpe schema show signed-inert-fixture-intent-v1.json
uv run bpe schema show inert-fixture-launch-attempt-receipt-v1.json
uv run bpe capabilities
printf '%s\n' '{"method":"capabilities","request_id":"probe-001","schema_version":"bpe.worker-request.v1"}' | uv run bpe-worker
```

On Linux x86-64, build and audit the fixed native launcher with:

```bash
make -C worker/linux/inert_fixture_launcher check
```

The internal evaluator checkout additionally contains the private task projection and test
suite, where maintainers run:

```bash
uv run pytest
uv run bpe task validate tasks/smoke/missing-null
uv run bpe task lint tasks/smoke/missing-null
```

Generate the committed schemas after changing a model:

```bash
uv run python scripts/export_schemas.py
```

## Metric contract

The headline metric is `pass@1`, where a task passes only if every required stage and every
check in the frozen scoring contract passes. The scorer rejects missing, duplicate,
unexpected, and vacuously empty required check sets. Independent-sample `pass@k` and
interactive multi-turn repair are different experiments and will never be reported under
the same name.

A strict anchored report additionally requires a precommitted experiment manifest: exact
suite, model and per-training-seed checkpoint artifacts, generation seeds, sample count,
sampling config, grader/environment, reward policy, and reported `k`. Those identities are
committed inside each replayed evaluation request, not merely attached while reporting.
Every replay must appear in an externally anchored registry that binds its evidence, grade,
scoring contract, and policy digests. A replay's internal hashes establish integrity, not
who produced it.

**Phase 0 never emits an official result**, even when all those integrity checks pass. The
current worker does not execute candidates on a real pinned kernel, and this repository
does not yet verify an authoritative evaluator's signed or append-only attestation channel.
Anchored Phase 0 reports exercise the fail-closed measurement pipeline and are always
labeled `official: false`.

Prepared evaluation jobs are likewise non-executable records. Their schema fixes
`execution_authorized: false` and `authoritative: false`, and exposes no host path, argv,
environment, archive, or dispatch field. Any future dispatcher must receive the manifest
digest from an external trust anchor before consuming the sealed bundle bytes; a bundle's
self-consistent hashes do not grant execution authority.

A signed dispatch authorization is separate from job v1. It authenticates a control-plane
decision and can be durably consumed once, but the current admission receipt is also
structurally non-executing and nonauthoritative. It is not a worker result, a snapshot
freshness proof, or permission for callers to spawn a compiler. See the
[Phase 1A boundary](docs/dispatch-admission.md).

Linux ingress proves that exact claim against the durable ledger, binds the signed ingress
policy, opens only the claim-derived digest tree with fail-closed `openat2` restrictions,
and copies verified bytes into a private worker object with no-replacement publication. Its
receipt remains local, unsigned, non-executing, and nonauthoritative. See the [Phase 1B.0
boundary](docs/linux-ingress.md).

Cgroup qualification is a separate unsigned host diagnostic. It validates one point-in-time
empty-leaf lifecycle below a pre-opened delegated root and only reports after the leaf has
been removed. Its exact controller readback does not prove process creation, live resource
enforcement, descendant cleanup, filesystem or network isolation, or launch authority. See
the [Phase 1B.1 boundary](docs/cgroup-qualification.md).

Phase 1B.2a separately authenticates and durably claims one short-lived intent describing a
future fixed spawned launcher and built-in no-exec fixture. The implementation is pure
Python and launches nothing. Its `claimed_not_started` receipt accepts no launcher or
executable path, argv, environment, job, candidate, or cgroup report. It binds one configured
worker/claim-ledger identity and explicitly requires a distinct future atomic launch ledger
plus original-intent and full-policy revalidation before any process. Its one-shot guarantee
is local to that durable physical ledger; deployment must prevent ledger cloning and
rollback. See [inert-fixture intent admission](docs/inert-fixture-admission.md).

Phase 1B.2b-0 reauthenticates that original signed intent and exact committed claim in a
separate physical launch ledger, serializes the worker clock against claim time and expiry,
and atomically consumes one attempt. Its canonical recovery receipt is terminal no-retry
evidence with every launch, process, execution, candidate/job-access, and authority field
fixed false. The API accepts no executable, process callback, argv, environment, cgroup,
job, or candidate surface; the receipt itself is not launch authority.

Likewise, dynamic-admission reports are structurally `provisional` and
`authoritative: false`. They validate supplied microVM-shaped evidence but do not establish
that a trusted worker produced it or that every run used a distinct restored snapshot. A
grader-qualification report has the same boundary: it verifies frozen counterexample
rankings but does not authenticate the supplied replay-shaped receipts, verify their full
artifact bytes, or prove calibration-before-validation chronology. A passing corpus
audit is only a result from the frozen static detector; it is not a claim
that forks, vendored copies, identifier-renamed code, or semantic/AST rewrites are absent.

RL reward is a separately versioned optimization signal. It can be changed by replaying
stored evidence without redefining historical benchmark success.

## Platform status

| Capability | macOS | Linux native | Pinned microVM |
|---|---:|---:|---:|
| Schema/task validation | yes | yes | yes |
| Pure scoring and replay integrity | yes | yes | yes |
| Static corpus contamination audit | yes | yes | yes |
| Provisional admission evidence verification | yes | yes | yes |
| Provisional grader qualification | yes | yes | yes |
| Pure typed XDP oracle derivation | yes | yes | yes |
| Bounded capability-only worker protocol | yes | yes | yes |
| Prepared evaluation job verification | yes | yes | yes |
| Signed one-shot dispatch admission | non-executing claim | non-executing claim | non-executing claim |
| Claimed-job worker ingress | explicit refusal | verified copy on x86-64 | provisioning/qualification pending |
| Cgroup-v2 empty-leaf qualification | explicit refusal | non-authorizing probe on x86-64 | provisioning/qualification pending |
| Inert-fixture intent admission | non-launching claim | non-launching claim | non-launching claim |
| Inert-fixture launch-attempt consumption | non-launching terminal claim | non-launching terminal claim | provisioning/qualification pending |
| Candidate compile/load in Phase 0 worker | no | no | no |
| Real kernel verifier | no | nonofficial diagnostics planned | planned authoritative path |
| Official benchmark eligibility | no | no | Phase 1 target |

`bpe capabilities` distinguishes host prerequisites from implemented worker operations. It
does not claim compile, load, verifier, or official support merely because Clang, bpftool,
or kernel BTF happens to be installed.

## License

MIT. Task corpora must additionally preserve their upstream provenance and license
metadata; a task without that metadata is rejected by the admission linter.
