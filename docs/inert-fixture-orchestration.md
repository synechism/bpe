# Atomic fixed-fixture orchestration

Phase 1B.2b-1 joins the previously separate inert-fixture boundaries for exactly one
built-in, no-exec diagnostic fixture. `bpe.inert_orchestration` reauthenticates the signed
intent and committed claim, seals and stages the configured launcher, validates a dedicated
Linux controller process, consumes the one-shot launch attempt, retains a configured cgroup
leaf, starts the fixed launcher, collects its bounded protocol, and performs terminal
cleanup. The public result schema is
[`linux-inert-fixture-orchestration-result-v1.json`](../schemas/linux-inert-fixture-orchestration-result-v1.json).

This is not a candidate runner. The API has no path, command, caller-selected argument or
environment, fixture selector, candidate, evaluation job, external fixture, or callback.
The fixture child is compiled into the trusted launcher and never performs `exec`.

## Public boundary

```python
def orchestrate_linux_inert_fixture(
    intent: SignedInertFixtureIntent,
    trust_store: InertFixtureIntentTrustStore,
    expectation: InertFixtureLaunchExpectation,
    claim_receipt: InertFixtureIntentClaimReceipt,
    claim_ledger: InertFixtureIntentLedger,
    cgroup_policy: LinuxCgroupV2QualificationPolicy,
    *,
    launch_ledger: InertFixtureLaunchLedger,
    launch_attempt_id: str,
    launcher_artifact_fd: int,
    delegated_root_fd: int,
) -> LinuxInertFixtureOrchestrationResult: ...
```

The caller retains ownership of both supplied descriptors. The deployment layer must bind
them to the configured launcher artifact and delegated-root labels; a string identifier in
the signed policy cannot by itself authenticate an already open descriptor.

## Atomic ordering

The ordering is the security property. Before mutating the launch ledger, creating a
cgroup, or creating a process, the orchestrator completes all of these steps:

1. freeze and cross-check the complete inert-fixture and cgroup policies;
2. read-only reauthenticate the original signed intent and exact committed claim against
   the configured claim ledger;
3. run immutable launcher-artifact preflight, create the sealed executable memfd, and
   stage a close-on-exec executable descriptor; and
4. validate the dedicated host process and install its child-subreaper guard.

A failure in that pre-consumption region raises an error and creates neither a retained
leaf nor a process. Only after every preflight succeeds does the orchestrator atomically
consume the separate launch ledger. It verifies the returned receipt against the committed
row before it retains a cgroup leaf. There is no path from a recovered receipt to launch:
recovery after an ambiguous commit or receipt-verification failure can produce only a
terminal no-launch observation.

After clean receipt verification, the lifecycle is fixed:

```text
retain and revalidate leaf
        -> duplicate leaf handoff fd
        -> fixed posix_spawn
        -> bounded transcript collection and exact launcher wait
        -> descriptor finalization, cgroup kill/empty/removal, descendant reap
        -> restore subreaper and construct the unsigned result
```

Every post-consumption failure is terminal and `retry_permitted` remains `false`. The
orchestrator never repairs drift, selects another leaf, substitutes another launcher, or
reopens the consumed attempt.

## Dedicated controller process

Host admission is intentionally restrictive. The call requires native Linux x86-64 with
the expected 64-bit ABI, procfs process state, `posix_spawn`/wait interfaces, atomic
`MSG_CMSG_CLOEXEC` receipt, and a soft `RLIMIT_NOFILE` of at least 64. It must run on the
main thread of a genuinely single-threaded process with default `SIGCHLD`, no existing
children, and no pre-existing child-subreaper state. The guard saves the exact libc
`SIGCHLD` action, reinstalls the default disposition before spawn to clear a hidden
`SA_NOCLDWAIT` flag, and restores the saved action only after the child set is empty.

Every ambient descriptor numbered 3 or above must be non-inheritable, and the highest
ambient descriptor must be below 32 so the fixed staging range is available. These are
point-in-time checks. The deployment must prevent concurrent threads, signal handlers, or
same-authority processes from changing descriptors or child state around the call.

The orchestrator temporarily becomes a child subreaper so it can account for an adopted
fixed-fixture descendant before returning. It restores the original non-subreaper and
`SIGCHLD` action state only after exact launcher disposition and the no-children audit permit
it. An unresolved launcher or descendant is cleanup failure, never success.

## Fixed launch ABI

The executable is addressed internally through `/proc/self/fd/<sealed-fd>`; no caller path
is accepted. `os.posix_spawn` receives exactly one argument whose `argv[0]` is
`bpe-inert-fixture-launcher`, an empty environment, an empty signal mask, and default signal
dispositions. Fixed file actions map only these child descriptors:

| Descriptor | Fixed object |
|---:|---|
| `0` | read-only `/dev/null` |
| `1` | write-only `/dev/null` |
| `2` | write-only `/dev/null` |
| `3` | one end of the close-on-exec Unix `SOCK_SEQPACKET` control socket |
| `4` | the fully revalidated retained cgroup leaf |

All staging sources and ambient descriptors are close-on-exec. The native launcher performs
its own exact descriptor, argument, environment, control-socket, and cgroup checks before
creating its built-in child. There is no dynamic loader, external fixture executable,
candidate, or job handoff.

## Deadlines and cleanup

The signature-verified fixture policy supplies `fixture_timeout_ms`,
`cleanup_timeout_ms`, and `total_timeout_ms`. One monotonic timeline starts after clean
launch-attempt consumption. Transcript collection and the ordinary launcher wait consume
the fixture interval. Termination and exact wait establish a cleanup deadline bounded by
both the remaining cleanup allowance and the overall deadline. Retained-cgroup cleanup and
adopted-descendant reaping share that remaining deadline rather than each starting a fresh
timeout.

The retained handle's `cleanup_with_timeout_ms(...)` performs the normal live-leaf
`cgroup.kill`, `populated 0`, identity, removal, and delegated-root audit with only the
remaining bounded time. If that budget is already exhausted, a one-millisecond safety
cleanup may still be attempted, but the result cannot claim the deadline was observed.
Userspace deadline checks cannot preempt an individual kernel syscall. The result therefore
records separate `cleanup_deadline_observed` and
`total_deadline_observed` facts; an overrun or incomplete descriptor, process, cgroup,
artifact, or subreaper cleanup forces `orchestrator_failed`.

The control channel is independently bounded to at most eight native socket records. A
captured payload is bounded to the fixed frame size plus one rejection byte, so short,
oversized, and empty malformed messages remain replayable without allowing unbounded input.
Each record preserves its payload and `recvmsg` truncation and ancillary-data facts.
Validation reruns the strict native transcript parser; it does not trust the stored parsed
projection.

## Ambiguous consumption and controller death

The launch-attempt ledger is the durable no-retry boundary. If admission raises when commit
may have completed, the orchestrator attempts read-only receipt recovery. A recovered,
fully bound receipt is evidence that the attempt was consumed, but it is deliberately not
used to retain a leaf or spawn the launcher. The normal return is an
`orchestrator_failed` no-launch result with failure stage `attempt_finalization`.

If a committed receipt cannot be recovered or trusted, the API raises
`LinuxInertFixtureTerminalConsumptionError`. That exception is not a receipt, but its
contract still requires the caller to treat the attempt as possibly consumed and never
retry it. A matching ledger reservation without receipt bytes is a terminal tombstone, not
permission to choose a new attempt ID.

Normally returned results are not crash records. A controller process can die after durable
consumption but before it serializes a result; in that case the only durable fact may be the
launch-ledger receipt or tombstone. The orchestrator does not install `PDEATHSIG`, and its
in-process cleanup cannot survive abrupt controller death. Production deployment therefore
needs an outer systemd unit or dedicated PID namespace with independently configured kill,
reap, and cgroup cleanup ownership.

## Result, replay, and nonclaims

`LinuxInertFixtureOrchestrationResult` has literal status
`fixture_orchestration_terminal_unsigned` and exactly three outcomes:

- `fixture_succeeded` requires an accepted successful native replay, retained-leaf handoff,
  exact launcher reap, complete cgroup and local cleanup, and both deadlines observed;
- `launcher_failed` requires an accepted native failure replay with the same complete
  lifecycle and deadline evidence; and
- `orchestrator_failed` closes an orchestration stage and reason, including recovered
  no-launch consumption, setup/spawn/protocol/wait failures, deadline overruns, or cleanup
  failure.

The domain-separated `result_id` covers the complete canonical result body, including the
full policies, artifact and launch-attempt receipts and their digests, cgroup identities,
raw native records, derived replay, lifecycle facts, deadline facts, and cleanup evidence.
Strict validation recomputes every nested digest and parser projection, enforces causal
state invariants, and caps canonical results at 64 KiB.

Content addressing supplies deterministic replay integrity, not provenance. Every result
is explicitly unsigned, freshness-unauthenticated, non-durable, unattested,
non-authoritative, ineligible for official grading, and absent from a finalization ledger.
It cannot authorize a retry or candidate launch. `execution_authorized: false` describes
that absence of authority; it does not erase the separately recorded fact that the trusted
diagnostic launcher and built-in child may have run. A later authoritative boundary needs
a distinct result-attestor trust role, authenticated freshness, an external containment
audit, and a durable result/finalization ledger.

This phase proves neither candidate execution nor general resource isolation. It does not
exercise real memory/PID/CPU pressure, a forking descendant tree, filesystem or network
isolation, a compiler, BPF loading, or the kernel verifier. Those remain separately reviewed
worker milestones.
