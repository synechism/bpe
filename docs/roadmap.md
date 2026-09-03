# Roadmap

## Phase 0 — grading contract (current)

- versioned schemas, frozen suite/experiment manifests, exact-check contracts, and task
  public/private projections;
- pure strict scorer and versioned reward;
- replay integrity, externally anchored attestation registries, and rescoring;
- exact-sample fail-closed aggregation and seed/cluster-aware uncertainty;
- explicitly nonofficial reports while the worker is capability-only;
- provisional dynamic-admission receipts over exact repair-task evidence matrices;
- provisional grader-qualification receipts over byte-sealed, identity-disjoint
  calibration/validation tasks, exact witness/control kill matrices, prepared jobs, and
  precommitted reward orderings;
- frozen closed-tree corpus manifests and a fail-closed static contamination detector;
- bounded capability-only worker transport with request/digest correlation;
- bounded, prepared-only evaluation job bundles with exact CAS closure, identity
  cross-binding, and descriptor-relative loading;
- typed, execution-free XDP differential-oracle contracts and deterministic first-divergence
  reports over return values, packet/context bytes, maps, ordered events, and counters;
- adversarial smoke task and cross-platform contract tests.

## Phase 1 — narrow authoritative worker

- typed zero-swap/no-network execution profiles and externally signed, short-lived,
  one-shot dispatch authorization with a durable atomic claim ledger (implemented, but
  structurally non-executing and nonauthoritative);
- worker-owned digest-addressed ingress using Linux x86-64 `openat2`, exact claim-ledger
  proof, verified byte-copy, and `renameat2(RENAME_NOREPLACE)` publication (implemented as
  a non-executing, nonauthoritative Phase 1B.0 boundary; deployment qualification remains);
- **Phase 1B.1 — implemented:** an unsigned, non-authorizing cgroup-v2 empty-leaf
  qualification report over a pre-opened exclusive systemd delegation. It checks the exact
  root/controller state, writes and reads back page-aligned `memory.max`, zero
  `memory.swap.max`, `pids.max`, `memory.oom.group`, fair-class `cpu.max` with zero burst,
  and zero depth/descendant limits, writes `cgroup.kill` only while the leaf is empty, and
  removes the leaf. It creates no process, exercises no limit, and proves neither
  descendant reclamation nor filesystem/network isolation;
- **Phase 1B.2a — implemented:** pure-Python Ed25519 admission for one fixed inert-fixture
  intent. It binds a future launcher artifact and seccomp policy, literal launcher and
  built-in fixture protocols, full typed policy, resources, deadlines, audience, worker,
  configured claim-ledger, distinct launch-ledger, and delegated-root identities, then
  consumes the intent once in that durable physical ledger. Its receipt is
  `claimed_not_started`, nonauthoritative, and cannot launch a process; a future launcher
  must use the signed distinct atomic launch ledger and revalidate the original intent and
  complete policy. Whole-ledger anti-rollback and uniqueness remain deployment invariants;
- **Phase 1B.2b-0 — implemented:** a separate, explicitly provisioned launch-attempt
  ledger reauthenticates the original signed intent and exact committed claim receipt,
  serializes the worker clock against claim time, expiry, and a durable high-water mark,
  and atomically consumes the only launch attempt. Its recoverable canonical receipt is
  `launch_attempt_consumed_not_started`: it is terminal no-retry evidence, not launch
  authority, and the API has no process, executable, cgroup, argv, environment, job, or
  candidate surface;
- **Phase 1B.2b-1 — fixed-fixture orchestration implemented; native x86-64
  qualification required:** a native x86-64
  `clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)` supervisor limited to a fixed inert
  fixture, with a fixed seccomp filter, cross-language bounded result protocol, and static
  ELF build gates. A process-free Python preflight authenticates the configured digest,
  exact ELF shape, and embedded seccomp markers, then copies the bytes into a completely
  sealed executable memfd and retains only a read-only fd. A blocking privileged disposable
  Linux CI probe is configured to exercise atomic cgroup birth, pidfd stop/exit observation
  and reaping, a live `cgroup.kill`, and `populated 0`. An evaluator-only inherited seccomp
  case denies both normal and emergency `pidfd_send_signal` calls with `EPERM`; its exact
  `0x1c3` error transcript and external reap/empty/removal checks evidence the emergency
  cleanup outcome under the fixed-child, trusted-kernel, single-writer assumptions. They do
  not independently prove the return from the emergency `cgroup.kill` write. A successful
  gate can emit a canonical replayable report only after strict cleanup, but that report is
  unsigned, freshness-unauthenticated, non-durable, and nonauthoritative. Qualification
  requires the gate to pass on a native x86-64 host; its code and configuration alone are
  not evidence. The atomic Python boundary now completes signed-intent/claim,
  immutable-artifact, and dedicated-host preflight before durable attempt consumption;
  verifies the committed receipt before cgroup retention; launches only the fixed
  descriptor `0..4`, single-argument, empty-environment ABI; and shares fixture, cleanup,
  and total monotonic deadlines through terminal cleanup. Ambiguous consumption never
  reaches launch and never permits retry. Its replayable terminal result is still unsigned,
  non-durable, freshness-unauthenticated, and nonauthoritative. Real controller pressure,
  forking-descendant cleanup, and abrupt-controller-death recovery remain later boundaries.
  The API accepts no caller argv, environment, executable path, candidate, job, external
  fixture, or callback. A distinct result-signing domain and durable result/finalization
  ledger must bind any terminal outcome without creating candidate-launch or retry
  authority;
- pinned Clang 18 single-file XDP compilation;
- ELF/BTF/object-policy inspection;
- static libbpf runner with per-program log buffers at verifier log level 2;
- `BPF_PROG_TEST_RUN` cases with fresh maps/objects;
- canonical packet/context/map/event traces;
- QEMU/KVM development image, then a fresh-process-per-restore Firecracker snapshot worker;
- reconnecting, framed, bounded vsock sessions with host-monotonic deadlines;
- authenticated evaluator attestations and the first official-result eligibility audit;
- per-run snapshot instance receipts, verified replay bundles, and mutation/inverse-edit
  causality in authoritative task admission;
- five hand-authored, fully admitted tasks.

## Phase 2 — data pipeline

- clean corpus harvesting with independently collected provenance and licenses;
- fork/vendoring analysis plus calibrated structural/AST clone detection;
- validation of the static token detector on disjoint repositories and candidate-producing
  transformations;
- AST mutation operators and revert validation;
- generated semantic obligations and exploit controls;
- first 200 functional tasks for the cheap-signal run.

## Phase 3 — training and evaluation

- SFT mutation/generation mix;
- multi-turn GRPO with raw-log versus bpfix observation ablation;
- 3B cheap-signal gate before full compute;
- bpfix-bench, held-out mutation, generation, and unseen-helper/program-type reports;
- three or more seeds and predeclared statistical analysis.
