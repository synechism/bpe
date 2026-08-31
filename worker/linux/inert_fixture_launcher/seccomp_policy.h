#ifndef BPE_INERT_FIXTURE_SECCOMP_POLICY_H
#define BPE_INERT_FIXTURE_SECCOMP_POLICY_H

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

#define BPE_INERT_SECCOMP_POLICY_ID "bpe.inert-fixture-launcher-seccomp.v1"

/*
 * This exact instruction macro is the single source for the installed filter and the
 * canonical filter-byte digest emitted by seccomp_policy_dump.c.  X receives the native
 * sock_filter fields (code, jt, jf, k).  On fixed x86-64, an unlisted syscall returns
 * EPERM; an architecture mismatch kills the process.
 */
#define BPE_INERT_SECCOMP_FILTER(X)                                                   \
    X(BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, arch))           \
    X(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_X86_64)                           \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS)                              \
    X(BPF_LD | BPF_W | BPF_ABS, 0, 0, offsetof(struct seccomp_data, nr))             \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_read)                                    \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_write)                                   \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_close)                                   \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_lseek)                                   \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_poll)                                    \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_ppoll)                                   \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_sendto)                                  \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_fcntl)                                   \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_clock_gettime)                           \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_pipe2)                                   \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_clone3)                                  \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_pidfd_send_signal)                       \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_waitid)                                  \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_close_range)                             \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_pause)                                   \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_prctl)                                   \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_restart_syscall)                         \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_rt_sigreturn)                            \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_exit)                                    \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_exit_group)                              \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW)                                     \
    X(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | (uint32_t)EPERM)

#endif
