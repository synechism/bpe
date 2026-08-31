# Immutable launcher artifact preflight

`bpe.inert_artifact` is the process-free boundary between a trusted deployment artifact
and the later one-shot inert-fixture orchestrator. It accepts the complete configured
`InertFixtureLaunchExpectation` plus one exact caller-supplied readable descriptor. It
accepts no launcher path, command, argument vector, environment, candidate, job, cgroup,
claim token, or process-creation callback.

The deployment layer is responsible for opening the configured file. The preflight API
cannot prove how the caller obtained that descriptor and therefore makes no claim that the
original pathname was caller-owned. It duplicates the supplied descriptor and requires a
root- or current-EUID-owned regular inode with one link, owner execute permission, no
group/other write permission, no special permission bits, read-only access, and a bounded
size. Because no pathname enters the API, symlink and pathname replacement races are
outside this boundary. A deployment that begins from a directory name must first resolve
the fixed component beneath its trusted pre-opened root with an equivalent `openat2`
no-symlink policy.

Preflight reads with `pread`, preserving the caller's file offset, and compares device,
inode, mode, UID, GID, link count, size, modification time, and change time before and after
the bounded read. It then requires the configured SHA-256, the fixed Linux ELF64
little-endian x86-64 static-PIE shape, and exactly one NUL-terminated copy of both the fixed
seccomp policy ID and its canonical filter digest. Marker checking is defense in depth; it
does not disassemble the artifact or independently prove which filter the launcher installs.
The trusted whole-artifact SHA-256 and the native build audit remain the binding from those
markers to executable behavior.

The verified bytes are copied into a fresh `MFD_EXEC | MFD_ALLOW_SEALING` memfd. The copy is
mode `0500` and must read back the exact seal mask `F_SEAL_SEAL | F_SEAL_SHRINK |
F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE | F_SEAL_EXEC`. It is reopened read-only
through a verified procfs `/proc/self/fd` directory, rehashed, and retained as the only
handoff artifact. `duplicate_executable_fd()` revalidates the inode, mode, link count,
access mode, close-on-exec state, and seals before returning a caller-owned CLOEXEC
descriptor suitable for a later `execveat(AT_EMPTY_PATH)` operation.

The retained handle must be closed deterministically, preferably with a `with` block. A
best-effort finalizer only limits accidental descriptor leaks; it is not lifecycle evidence.
The receipt's `executable_fd_retained_at_preflight: true` records only the instant the
preflight completed. A detached or serialized receipt never proves that descriptor remains
live; only a successful locked `duplicate_executable_fd()` call on the original handle
establishes a current handoff descriptor.
Preflight does not consume the launch ledger, create a cgroup, create a process, authorize a
launch, or produce authoritative qualification evidence. The orchestration boundary must
complete this preflight before consuming the one-shot launch attempt, then treat every
failure after consumption as terminal.

There is no portable or less-sealed fallback. A non-Linux host, non-x86-64 ABI, older
kernel without executable memfds or execute seals, unverified procfs, unexpected ELF,
digest mismatch, metadata drift, or seal/readback mismatch fails closed.
