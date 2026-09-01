# Fixed inert-fixture launcher

This directory contains the separately compiled Phase 1B.2b Linux x86-64 launcher. It is
not a generic process runner. It accepts no request frame, executable path, command, extra
argv element, environment entry, candidate byte, evaluation job, or resource-policy input.
The already-authorized parent starts it once; the launcher immediately runs one compiled-in
no-exec fixture state machine.

The result is local unsigned qualification evidence. It is not a launch token, retry token,
candidate-execution result, or authoritative grading evidence.

## Startup ABI

The launcher fails closed unless all of these are exact at `main`:

- `argc == 1`, `argv[0] == "bpe-inert-fixture-launcher"`, and `argv[1] == NULL`;
- the environment is empty;
- descriptors 0, 1, and 2 are Linux `/dev/null` character devices, with stdin opened
  read-only and stdout/stderr opened write-only;
- descriptor 3 is one connected, non-listening `AF_UNIX/SOCK_SEQPACKET` socket;
- descriptor 4 is one read-only, non-`O_PATH` cgroup-v2 directory descriptor; and
- no descriptor numbered 5 or higher is open. Before opening any other resource, the
  launcher opens a fresh `/proc/self/fd` directory description as descriptor 5, verifies
  that it is procfs, enumerates it to EOF with raw `getdents64`, and requires the numeric
  set to be exactly descriptors 0 through 5. This remains complete even if a parent opened
  a high descriptor and then lowered `RLIMIT_NOFILE`; the launcher rejects rather than
  silently closing an unexpected inherited descriptor.

Descriptors 3 and 4 must not have `FD_CLOEXEC` before launch, because they cross the launcher
`exec`. The launcher sets it immediately after validation. The parent must create the exact
table before execution and retain its peer of descriptor 3.

The launcher binary must be executed from the same pinned bytes that were hashed. A caller
must use an already-verified immutable root-owned inode or an fd-based `execveat(...,
AT_EMPTY_PATH)`/equivalent flow; hashing a pathname and later executing that pathname is not
an acceptable preflight. `bpe.inert_artifact` now provides the process-free deployment
preflight: it verifies the configured digest, ELF and embedded seccomp markers, copies the
bytes into a completely sealed executable memfd, and retains only a read-only descriptor.
Atomic launch orchestration remains separate and pending. The build emits a static PIE so
no runtime ELF interpreter or shared-library path participates.

## Fixed kernel sequence

Only the launcher remains outside the supplied cgroup. It opens the fixed cgroupfs component
names `cgroup.events`, `cgroup.kill`, and `cgroup.procs` relative to descriptor 4, requires
both `populated 0` and an empty `cgroup.procs`, and then calls the raw x86-64 `clone3`
syscall with an all-zero 88-byte `clone_args` except:

- `flags = CLONE_INTO_CGROUP | CLONE_PIDFD` (`0x200001000`);
- `pidfd` points to one parent integer;
- `exit_signal = SIGCHLD`; and
- `cgroup = 4`.

There is no `fork`, `exec`, clone fallback, PID-based signal, pathname migration, or write to
`cgroup.procs`. The child closes every inherited/internal descriptor except a fixed readiness
pipe, emits one eight-byte ready record, closes that pipe, and blocks in the compiled-in
state machine. The parent requires both the exact success record and EOF on the readiness
pipe before it accepts child readiness.

After observing readiness and `populated 1`, the parent requires `cgroup.procs` to contain
the child PID as its exact sole entry. It then sends `SIGSTOP` with
`pidfd_send_signal` and requires `waitid(P_PIDFD, WSTOPPED | WNOWAIT)` to report
`CLD_STOPPED/SIGSTOP`. While the sole child is still populated, it writes exactly `1` to
`cgroup.kill`. It then requires pidfd exit observation to report `CLD_KILLED/SIGKILL`,
requires `cgroup.events` to reach `populated 0`, and reaps with `waitid(P_PIDFD, WEXITED)`.
Every post-clone error enters the same bounded best-effort pidfd/cgroup kill and pidfd reap
path. It never calls `kill(pid)` or `waitpid(pid)`.

If emergency child cleanup or owned-descriptor closure is incomplete, the terminal
`CLEANUP_INCOMPLETE` reason takes precedence over the earlier diagnostic reason. The
achieved-bit mask still preserves the successfully observed lifecycle prefix; an earlier
failure is never allowed to conceal an unproved reap, empty cgroup, or descriptor cleanup.

This submilestone intentionally does not fork a descendant or exercise memory, CPU, pids, or
output pressure. Those claims remain false for Phase 1B.2c.

## Protocol and deadlines

[`protocol.h`](protocol.h) is the 64-byte, network-byte-order, `SOCK_SEQPACKET` wire ABI.
It is launcher-to-parent only; any inbound byte is a protocol failure. Success is exactly
five contiguous records with sequence numbers 0 through 4: `HELLO`, `CHILD_READY`,
`CHILD_SIGNALED`, `CHILD_OBSERVED`, and `FINAL`. A failure emits at most one terminal
`ERROR`, whose `value0` is the achieved-bit subset, `value1` is zero, and bounded errno is
zero or at most Linux `MAX_ERRNO` 4095. No frame contains text or a path.
Startup validation consumes the first prohibited inbound record before failing so the fixed
single-record adversary observes an empty transcript followed by orderly peer EOF, never a
record derived from attacker-controlled content.

The parent remains responsible for the signed dynamic timeout. The C launcher has only a
five-second startup descriptor-scan ceiling, a 30-second fixed post-`HELLO` fixture-sequence
ceiling, and a separate five-second failure-cleanup ceiling; it does not claim those
constants are the signed policy values or a single overall wall bound. Kernel syscalls are
not preempted by these userspace poll deadlines. Successful `FINAL.value0` is exactly
`0x1ff`; `FINAL.value1` is elapsed monotonic nanoseconds.

`CHILD_OBSERVATION_FAILED` is valid only at the three observation checkpoints
`CHILD_READY`, `PIDFD_SIGNAL`, and `CHILD_OBSERVATION`. The orchestration contract assumes
one trusted writer for the retained leaf during this sequence; the launcher still checks
empty membership before `clone3` and exact sole-child membership before readiness and the
live `cgroup.kill` write.

The Python transcript parser accepts only the exact failure states reachable from this C
state machine. Its grammar is keyed by the count of preceding success frames, reason,
stage, and the complete achieved mask after emergency cleanup. It also enforces the
deterministic zero-errno cases, syscall-only nonzero cases, and the launcher's Linux
`clone3` errno classification. A combination of individually valid enum values and result
bits is not sufficient.

The collector must drain descriptor 3 through peer EOF and pass that observation plus the
exact spawned launcher PID into the parser. `HELLO` must name that same PID. A canonical
prefix and matching process return code without observed EOF is not a complete transcript.

## Seccomp and build

The launcher sets `PR_SET_NO_NEW_PRIVS`, installs the fixed filter generated from the exact
instruction macro in [`seccomp_policy.h`](seccomp_policy.h), and confirms both
no-new-privileges and filter mode before `clone3`. It fails closed if the host or an outer
policy prevents any step. [`seccomp_filter.h`](seccomp_filter.h) is the single array
definition consumed by both the launcher and the build-time dumper.
[`seccomp_policy_digest.h`](seccomp_policy_digest.h) embeds the SHA-256 of the canonical
big-endian `(code, jt, jf, k)` bytes for every installed instruction; `make check` rebuilds
those bytes from the same array and rejects any digest mismatch. The separately pinned
launcher-artifact digest binds the complete binary. Deployment must configure the signed
seccomp-policy digest to the verified embedded policy digest; neither digest is supplied by
a runtime caller.

Build on Linux x86-64 with a toolchain providing static libc:

```sh
make -C worker/linux/inert_fixture_launcher check
```

The output is `build/native/inert_fixture_launcher/bpe-inert-fixture-launcher`. The build
checks the canonical seccomp filter digest and embedded identity markers, ELF64
little-endian x86-64 PIE type,
absence of interpreter/shared-library/search-path dependencies, non-executable GNU stack,
RELRO, immediate binding, PIE flag, and SHA-1 build ID.

## Privileged live-kernel gate

The internal evaluator probe `tests/integration/inert_fixture_launcher_native_probe.py`
is the isolated blocking end-to-end kernel gate. It is not included in public release
archives. A public artifact therefore cannot by itself prove that this internal gate passed.
After ordinary CI succeeds for a same-repository `main` push, a separate trusted
`workflow_run` controller is configured to run it as root/PID 1 in a disposable privileged
Linux x86-64 container with private PID and cgroup namespaces and no network. The controller
first requires both the runner host and Docker server
to report native x86-64, so emulation is not accepted as qualification evidence. The probe
moves itself into a manager cgroup, creates a new empty sibling leaf per case, constructs the
exact empty-environment/argv0/descriptor-0-through-4 ABI, drains every `SOCK_SEQPACKET`
record through EOF, waits for the exact
launcher PID, and validates the result with the installed Python parser. The workflow passes
an external digest of the built artifact; the rootful probe copies those exact bytes into a
fresh root-owned mode-0500 file, runs the production immutable-artifact preflight, and uses a
fresh validated duplicate of that sealed read-only memfd for every fd-capable `execve` case.
The high close-on-exec artifact fd therefore cannot leak into the launcher's descriptor
table, and source-inode mutation cannot change executed bytes after preflight. Success
requires mask `0x1ff`, the exact child PID lifecycle, no reparented or zombie child,
`populated 0`, empty `cgroup.procs`, strict manager-cgroup removal, and a removable leaf.
Separate fresh leaves
require fail-closed behavior for an inherited descriptor 257, prequeued inbound control
data, and a peer closed before `exec`. A fifth leaf adds an adversarial evaluator-only
inherited outer seccomp filter immediately before fd-exec. That filter allows the native
x86-64 ABI except for `pidfd_send_signal`, which returns `EPERM`; it is not part of the
production launcher or its embedded policy. A successful native run must then parse the
exact `HELLO`, `CHILD_READY`, `ERROR` transcript with
`PIDFD_SIGNAL/PIDFD_SIGNAL_FAILED/EPERM`, kernel exit code, and achieved mask `0x1c3`, before
independently proving exact reap, an empty/removable leaf, and no reparented child. Passing
that live case supplies conditional evidence for the launcher's bounded emergency cleanup
outcome under the fixed-child, trusted-kernel, single-writer assumptions when both its normal
pidfd stop and emergency pidfd kill are denied. The transcript does not independently prove
the return from the `cgroup.kill` write; merely having the probe code does not provide any
run evidence.

This gate cannot run meaningfully in the ordinary unprivileged unit-test environment: it
requires a writable cgroup-v2 namespace, `CAP_SYS_ADMIN`, `CLONE_INTO_CGROUP`, pidfds,
`cgroup.kill`, and the native x86-64 seccomp/syscall ABI. The compile-time protocol,
descriptor-scan, seccomp-digest, and ELF checks remain unprivileged `make check` coverage;
passing those checks is not a substitute for the privileged live-kernel gate. Architecture
emulation is not release evidence because it may not implement fd-based `execve`, `clone3`,
pidfds, or the fixed seccomp syscall ABI faithfully.
Only a successful privileged run on a native x86-64 CI host qualifies the lifecycle; probe
and workflow presence do not.
