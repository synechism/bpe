#define _GNU_SOURCE

#include "protocol.h"
#include "seccomp_filter.h"
#include "seccomp_policy.h"
#include "seccomp_policy_digest.h"
#include "wire.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "bpe-inert-fixture-launcher supports only Linux x86-64"
#endif

#if !defined(SYS_clone3) || !defined(SYS_pidfd_send_signal) || !defined(SYS_close_range) || \
    !defined(SYS_getdents64)
#error "the Linux headers do not expose the required fixed syscall ABI"
#endif

#define BPE_LAUNCHER_ARGV0 "bpe-inert-fixture-launcher"
#define BPE_STARTUP_SCAN_TIMEOUT_MS UINT64_C(5000)
#define BPE_PROC_FD_PATH "/proc/self/fd"
#define BPE_PROC_FD_BUFFER_SIZE 4096U
#define BPE_PROC_FD_SCAN_FD 5
#define BPE_CHILD_RECORD_SIZE 8U
#define BPE_CGROUP_EVENTS_FD 5
#define BPE_CGROUP_KILL_FD 6
#define BPE_CGROUP_PROCS_FD 7
#define BPE_CHILD_READY_READ_FD 8
#define BPE_CHILD_READY_WRITE_FD 9
#define BPE_EXPECTED_PIDFD 10
#define BPE_P_PIDFD 3
#define BPE_CLONE_FLAGS (CLONE_INTO_CGROUP | CLONE_PIDFD)

_Static_assert(SYS_clone3 == 435, "unexpected x86-64 clone3 syscall number");
_Static_assert(SYS_pidfd_send_signal == 424,
               "unexpected x86-64 pidfd_send_signal syscall number");
_Static_assert(SYS_waitid == 247, "unexpected x86-64 waitid syscall number");
_Static_assert(SYS_getdents64 == 217, "unexpected x86-64 getdents64 syscall number");
_Static_assert(SYS_close_range == 436, "unexpected x86-64 close_range syscall number");
_Static_assert(CLONE_PIDFD == UINT64_C(0x1000), "unexpected CLONE_PIDFD value");
_Static_assert(CLONE_INTO_CGROUP == (UINT64_C(1) << 33),
               "unexpected CLONE_INTO_CGROUP value");
_Static_assert(BPE_CLONE_FLAGS == UINT64_C(0x200001000),
               "unexpected fixed clone3 flag mask");
_Static_assert(BPE_INERT_ACHIEVED_MASK == UINT64_C(0x1ff),
               "unexpected terminal achieved mask");
_Static_assert(O_PATH == 010000000, "unexpected Linux O_PATH value");
_Static_assert(P_PIDFD == BPE_P_PIDFD, "unexpected P_PIDFD waitid selector");
_Static_assert(SIGCHLD == 17 && SIGKILL == 9 && SIGSTOP == 19,
               "unexpected x86-64 Linux signal values");
_Static_assert(CLD_KILLED == 2 && CLD_STOPPED == 5,
               "unexpected x86-64 Linux wait codes");

struct bpe_clone_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
};

struct bpe_linux_dirent64 {
    uint64_t inode;
    int64_t offset;
    unsigned short record_length;
    unsigned char type;
    char name[];
};

_Static_assert(sizeof(struct bpe_clone_args) == 88U,
               "clone3 arguments must use the 88-byte VER2 ABI");
_Static_assert(offsetof(struct bpe_clone_args, cgroup) == 80U,
               "clone3 cgroup field has an unexpected offset");
_Static_assert(offsetof(struct bpe_linux_dirent64, name) == 19U,
               "getdents64 name offset has an unexpected value");

struct bpe_failure {
    uint32_t stage;
    uint32_t reason;
    int error_number;
};

struct bpe_events {
    int populated;
    int frozen;
    bool saw_frozen;
};

enum bpe_procs_match {
    BPE_PROCS_ERROR = -1,
    BPE_PROCS_MISMATCH = 0,
    BPE_PROCS_MATCH = 1,
};

struct bpe_runtime {
    int events_fd;
    int kill_fd;
    int procs_fd;
    int ready_read_fd;
    int ready_write_fd;
    int pidfd;
    pid_t launcher_pid;
    pid_t child_pid;
    uint64_t sequence;
    uint64_t achieved;
    uint64_t started_ns;
    bool control_usable;
    bool cgroup_usable;
    bool peer_open;
    bool child_created;
    bool child_reaped;
};

static const char bpe_embedded_seccomp_policy_id[] __attribute__((used)) =
    BPE_INERT_SECCOMP_POLICY_ID;
static const char bpe_embedded_seccomp_policy_sha256[] __attribute__((used)) =
    BPE_INERT_SECCOMP_POLICY_SHA256;

static void bpe_set_failure(struct bpe_failure *failure, uint32_t stage, uint32_t reason,
                            int error_number) {
    if (failure->reason != BPE_INERT_REASON_NONE) {
        return;
    }
    failure->stage = stage;
    failure->reason = reason;
    failure->error_number = error_number;
}

static uint32_t bpe_wire_errno(int error_number) {
    if (error_number < 1 || error_number > (int)BPE_INERT_MAX_ERRNO) {
        return 0U;
    }
    return (uint32_t)error_number;
}

static int bpe_exit_for_reason(uint32_t reason) {
    if (reason >= BPE_INERT_REASON_BAD_ARGC && reason <= BPE_INERT_REASON_CGROUP_NOT_EMPTY) {
        return BPE_INERT_EXIT_STARTUP;
    }
    if (reason >= BPE_INERT_REASON_PROTOCOL_INPUT && reason <= BPE_INERT_REASON_PEER_CLOSED) {
        return BPE_INERT_EXIT_PROTOCOL;
    }
    if ((reason >= BPE_INERT_REASON_RESOURCE_EXHAUSTED &&
         reason <= BPE_INERT_REASON_CHILD_REAP_FAILED) ||
        reason == BPE_INERT_REASON_IO_FAILURE) {
        return BPE_INERT_EXIT_KERNEL;
    }
    if (reason == BPE_INERT_REASON_TIMEOUT) {
        return BPE_INERT_EXIT_TIMEOUT;
    }
    if (reason == BPE_INERT_REASON_CLEANUP_INCOMPLETE) {
        return BPE_INERT_EXIT_CLEANUP;
    }
    return BPE_INERT_EXIT_INTERNAL;
}

static bool bpe_emit_frame(struct bpe_runtime *runtime, uint16_t type, uint32_t status,
                           uint32_t stage, uint32_t reason, uint32_t error_number,
                           uint64_t value0, uint64_t value1) {
    uint8_t frame[BPE_INERT_PROTOCOL_FRAME_SIZE];
    unsigned int interruptions = 0U;
    ssize_t sent;

    if (!runtime->control_usable || !runtime->peer_open ||
        runtime->sequence >= BPE_INERT_PROTOCOL_MAX_FRAMES) {
        return false;
    }
    bpe_inert_encode_frame(frame, type, runtime->sequence, status, stage, reason,
                           error_number, value0, value1);

    do {
        sent = send(BPE_INERT_CONTROL_FD, frame, sizeof(frame),
                    MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent >= 0 || errno != EINTR) {
            break;
        }
        interruptions++;
    } while (interruptions < 8U);
    if (sent != (ssize_t)sizeof(frame)) {
        return false;
    }
    runtime->sequence++;
    return true;
}

static bool bpe_monotonic_ns(uint64_t *result) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 || now.tv_nsec < 0 ||
        now.tv_nsec >= 1000000000L || (uint64_t)now.tv_sec > UINT64_MAX / UINT64_C(1000000000)) {
        return false;
    }
    *result = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    return true;
}

static bool bpe_deadline_after_ms(uint64_t milliseconds, uint64_t *deadline) {
    uint64_t now;
    uint64_t delta;
    if (!bpe_monotonic_ns(&now) || milliseconds > UINT64_MAX / UINT64_C(1000000)) {
        return false;
    }
    delta = milliseconds * UINT64_C(1000000);
    if (now > UINT64_MAX - delta) {
        return false;
    }
    *deadline = now + delta;
    return true;
}

static int bpe_deadline_poll_ms(uint64_t deadline, int maximum_ms) {
    uint64_t now;
    uint64_t remaining;
    uint64_t milliseconds;
    if (!bpe_monotonic_ns(&now) || now >= deadline) {
        return 0;
    }
    remaining = deadline - now;
    milliseconds = (remaining + UINT64_C(999999)) / UINT64_C(1000000);
    if (milliseconds > (uint64_t)maximum_ms) {
        milliseconds = (uint64_t)maximum_ms;
    }
    return (int)milliseconds;
}

static uint64_t bpe_elapsed_ns(const struct bpe_runtime *runtime) {
    uint64_t now;
    if (!bpe_monotonic_ns(&now) || now < runtime->started_ns) {
        return 0U;
    }
    return now - runtime->started_ns;
}

static bool bpe_exact_argv0(const char *value) {
    static const char expected[] = BPE_LAUNCHER_ARGV0;
    return value != NULL && strcmp(value, expected) == 0;
}

static bool bpe_validate_stdio_fd(int descriptor, int expected_access) {
    struct stat metadata;
    int descriptor_flags;
    int status_flags;
    if (fstat(descriptor, &metadata) != 0 || !S_ISCHR(metadata.st_mode) ||
        major(metadata.st_rdev) != 1U || minor(metadata.st_rdev) != 3U) {
        return false;
    }
    descriptor_flags = fcntl(descriptor, F_GETFD);
    status_flags = fcntl(descriptor, F_GETFL);
    return descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) == 0 &&
           status_flags >= 0 && (status_flags & O_PATH) == 0 &&
           (status_flags & O_ACCMODE) == expected_access;
}

static bool bpe_validate_control_fd(struct bpe_runtime *runtime) {
    int descriptor_flags;
    int status_flags;
    int socket_type = 0;
    int accept_connections = 0;
    socklen_t integer_length = sizeof(socket_type);
    struct sockaddr_storage local_address;
    struct sockaddr_storage peer_address;
    socklen_t local_length = sizeof(local_address);
    socklen_t peer_length = sizeof(peer_address);
    uint8_t unexpected;
    ssize_t received;

    descriptor_flags = fcntl(BPE_INERT_CONTROL_FD, F_GETFD);
    status_flags = fcntl(BPE_INERT_CONTROL_FD, F_GETFL);
    if (descriptor_flags < 0 || (descriptor_flags & FD_CLOEXEC) != 0 || status_flags < 0 ||
        (status_flags & O_ACCMODE) != O_RDWR ||
        getsockopt(BPE_INERT_CONTROL_FD, SOL_SOCKET, SO_TYPE, &socket_type, &integer_length) !=
            0 ||
        integer_length != sizeof(socket_type) || socket_type != SOCK_SEQPACKET) {
        return false;
    }
    integer_length = sizeof(accept_connections);
    if (getsockopt(BPE_INERT_CONTROL_FD, SOL_SOCKET, SO_ACCEPTCONN, &accept_connections,
                   &integer_length) != 0 ||
        integer_length != sizeof(accept_connections) || accept_connections != 0 ||
        getsockname(BPE_INERT_CONTROL_FD, (struct sockaddr *)&local_address, &local_length) !=
            0 ||
        getpeername(BPE_INERT_CONTROL_FD, (struct sockaddr *)&peer_address, &peer_length) != 0 ||
        local_length < sizeof(sa_family_t) || peer_length < sizeof(sa_family_t) ||
        local_address.ss_family != AF_UNIX || peer_address.ss_family != AF_UNIX) {
        return false;
    }
    received = recv(BPE_INERT_CONTROL_FD, &unexpected, sizeof(unexpected), MSG_DONTWAIT);
    if (received == 0) {
        runtime->peer_open = false;
        return false;
    }
    if (received > 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
        return false;
    }
    if (fcntl(BPE_INERT_CONTROL_FD, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0 ||
        fcntl(BPE_INERT_CONTROL_FD, F_SETFL, status_flags | O_NONBLOCK) != 0) {
        return false;
    }
    runtime->control_usable = true;
    return true;
}

static bool bpe_validate_cgroup_fd(struct bpe_runtime *runtime) {
    struct stat metadata;
    struct statfs filesystem;
    int descriptor_flags = fcntl(BPE_INERT_CGROUP_FD, F_GETFD);
    int status_flags = fcntl(BPE_INERT_CGROUP_FD, F_GETFL);
    if (descriptor_flags < 0 || (descriptor_flags & FD_CLOEXEC) != 0 || status_flags < 0 ||
        (status_flags & O_PATH) != 0 ||
        (status_flags & O_ACCMODE) != O_RDONLY || fstat(BPE_INERT_CGROUP_FD, &metadata) != 0 ||
        !S_ISDIR(metadata.st_mode) || fstatfs(BPE_INERT_CGROUP_FD, &filesystem) != 0 ||
        (uint64_t)filesystem.f_type != (uint64_t)CGROUP2_SUPER_MAGIC) {
        return false;
    }
    if (fcntl(BPE_INERT_CGROUP_FD, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
        return false;
    }
    runtime->cgroup_usable = true;
    return true;
}

static bool bpe_parse_fd_name(const char *name, size_t length, int *descriptor) {
    uint64_t parsed = 0U;
    size_t index;
    if (length == 0U || (length > 1U && name[0] == '0')) {
        return false;
    }
    for (index = 0U; index < length; index++) {
        unsigned char character = (unsigned char)name[index];
        if (character < (unsigned char)'0' || character > (unsigned char)'9' ||
            parsed > (uint64_t)INT_MAX / UINT64_C(10)) {
            return false;
        }
        parsed = parsed * UINT64_C(10) + (uint64_t)(character - (unsigned char)'0');
        if (parsed > (uint64_t)INT_MAX) {
            return false;
        }
    }
    *descriptor = (int)parsed;
    return true;
}

static bool bpe_validate_no_extra_fds(struct bpe_failure *failure) {
    _Alignas(struct bpe_linux_dirent64) uint8_t buffer[BPE_PROC_FD_BUFFER_SIZE];
    uint64_t deadline;
    struct stat metadata;
    struct statfs filesystem;
    uint32_t seen_descriptors = 0U;
    int directory_fd = -1;
    int failure_errno = 0;
    bool valid = false;

    if (!bpe_deadline_after_ms(BPE_STARTUP_SCAN_TIMEOUT_MS, &deadline)) {
        failure_errno = errno;
        goto finished;
    }
    directory_fd = open(BPE_PROC_FD_PATH,
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd != BPE_PROC_FD_SCAN_FD ||
        fstat(directory_fd, &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
        fstatfs(directory_fd, &filesystem) != 0 ||
        (uint64_t)filesystem.f_type != (uint64_t)PROC_SUPER_MAGIC) {
        failure_errno = directory_fd < 0 ? errno : 0;
        goto finished;
    }

    for (;;) {
        long length;
        size_t position = 0U;
        unsigned int interruptions = 0U;
        do {
            length = syscall(SYS_getdents64, directory_fd, buffer, sizeof(buffer));
            if (length >= 0 || errno != EINTR) {
                break;
            }
            interruptions++;
        } while (interruptions < 8U);
        if (length < 0) {
            failure_errno = errno;
            goto finished;
        }
        if (length == 0) {
            break;
        }
        while (position < (size_t)length) {
            const struct bpe_linux_dirent64 *entry;
            const char *terminator;
            size_t remaining = (size_t)length - position;
            size_t name_capacity;
            size_t name_length;
            int descriptor;
            uint32_t descriptor_bit;

            if (remaining < offsetof(struct bpe_linux_dirent64, name) + 2U) {
                goto finished;
            }
            entry = (const struct bpe_linux_dirent64 *)(const void *)(buffer + position);
            if ((size_t)entry->record_length > remaining ||
                entry->record_length < offsetof(struct bpe_linux_dirent64, name) + 2U) {
                goto finished;
            }
            name_capacity = (size_t)entry->record_length -
                            offsetof(struct bpe_linux_dirent64, name);
            terminator = memchr(entry->name, '\0', name_capacity);
            if (terminator == NULL) {
                goto finished;
            }
            name_length = (size_t)(terminator - entry->name);
            if ((name_length == 1U && entry->name[0] == '.') ||
                (name_length == 2U && entry->name[0] == '.' &&
                 entry->name[1] == '.')) {
                position += (size_t)entry->record_length;
                continue;
            }
            if (!bpe_parse_fd_name(entry->name, name_length, &descriptor) ||
                descriptor < 0 || descriptor > BPE_PROC_FD_SCAN_FD) {
                goto finished;
            }
            descriptor_bit = UINT32_C(1) << (unsigned int)descriptor;
            if ((seen_descriptors & descriptor_bit) != 0U) {
                goto finished;
            }
            seen_descriptors |= descriptor_bit;
            position += (size_t)entry->record_length;
        }
        if (bpe_deadline_poll_ms(deadline, 1) == 0) {
            goto finished;
        }
    }
    valid = seen_descriptors == UINT32_C(0x3f);

finished:
    if (directory_fd >= 0 && close(directory_fd) != 0) {
        failure_errno = errno;
        valid = false;
    }
    if (!valid) {
        bpe_set_failure(failure, BPE_INERT_STAGE_DESCRIPTOR_VALIDATION,
                        BPE_INERT_REASON_BAD_DESCRIPTOR_LAYOUT, failure_errno);
    }
    return valid;
}

static bool bpe_validate_startup_fds(struct bpe_runtime *runtime,
                                     struct bpe_failure *failure) {
    if (!bpe_validate_stdio_fd(STDIN_FILENO, O_RDONLY) ||
        !bpe_validate_stdio_fd(STDOUT_FILENO, O_WRONLY) ||
        !bpe_validate_stdio_fd(STDERR_FILENO, O_WRONLY)) {
        bpe_set_failure(failure, BPE_INERT_STAGE_DESCRIPTOR_VALIDATION,
                        BPE_INERT_REASON_BAD_STDIO, errno);
        return false;
    }
    if (!bpe_validate_control_fd(runtime)) {
        bpe_set_failure(failure, BPE_INERT_STAGE_DESCRIPTOR_VALIDATION,
                        runtime->peer_open ? BPE_INERT_REASON_BAD_CONTROL_SOCKET
                                           : BPE_INERT_REASON_PEER_CLOSED,
                        errno);
        return false;
    }
    if (!bpe_validate_cgroup_fd(runtime)) {
        bpe_set_failure(failure, BPE_INERT_STAGE_DESCRIPTOR_VALIDATION,
                        BPE_INERT_REASON_BAD_CGROUP_DESCRIPTOR, errno);
        return false;
    }
    return bpe_validate_no_extra_fds(failure);
}

static bool bpe_open_cgroup_files(struct bpe_runtime *runtime, struct bpe_failure *failure) {
    struct stat metadata;
    runtime->events_fd = openat(BPE_INERT_CGROUP_FD, "cgroup.events",
                                O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    if (runtime->events_fd != BPE_CGROUP_EVENTS_FD ||
        fstat(runtime->events_fd, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode)) {
        bpe_set_failure(failure, BPE_INERT_STAGE_CGROUP_VALIDATION,
                        BPE_INERT_REASON_BAD_CGROUP_DESCRIPTOR, errno);
        return false;
    }
    runtime->kill_fd = openat(BPE_INERT_CGROUP_FD, "cgroup.kill",
                              O_WRONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    if (runtime->kill_fd != BPE_CGROUP_KILL_FD ||
        fstat(runtime->kill_fd, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode)) {
        bpe_set_failure(failure, BPE_INERT_STAGE_CGROUP_VALIDATION,
                        BPE_INERT_REASON_BAD_CGROUP_DESCRIPTOR, errno);
        return false;
    }
    runtime->procs_fd = openat(BPE_INERT_CGROUP_FD, "cgroup.procs",
                               O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    if (runtime->procs_fd != BPE_CGROUP_PROCS_FD ||
        fstat(runtime->procs_fd, &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
        bpe_set_failure(failure, BPE_INERT_STAGE_CGROUP_VALIDATION,
                        BPE_INERT_REASON_BAD_CGROUP_DESCRIPTOR, errno);
        return false;
    }
    return true;
}

static bool bpe_parse_events(const uint8_t *input, size_t length, struct bpe_events *events) {
    size_t offset = 0U;
    bool saw_populated = false;
    events->populated = -1;
    events->frozen = -1;
    events->saw_frozen = false;
    if (length == 0U || input[length - 1U] != '\n') {
        return false;
    }
    while (offset < length) {
        size_t end = offset;
        size_t line_length;
        while (end < length && input[end] != '\n') {
            end++;
        }
        if (end == length) {
            return false;
        }
        line_length = end - offset;
        if (line_length == sizeof("populated 0") - 1U &&
            memcmp(input + offset, "populated ", sizeof("populated ") - 1U) == 0 &&
            (input[end - 1U] == '0' || input[end - 1U] == '1') && !saw_populated) {
            events->populated = input[end - 1U] - '0';
            saw_populated = true;
        } else if (line_length == sizeof("frozen 0") - 1U &&
                   memcmp(input + offset, "frozen ", sizeof("frozen ") - 1U) == 0 &&
                   (input[end - 1U] == '0' || input[end - 1U] == '1') &&
                   !events->saw_frozen) {
            events->frozen = input[end - 1U] - '0';
            events->saw_frozen = true;
        } else {
            return false;
        }
        offset = end + 1U;
    }
    return saw_populated && (!events->saw_frozen || events->frozen == 0);
}

static bool bpe_read_events(int descriptor, struct bpe_events *events) {
    uint8_t buffer[128];
    uint8_t overflow;
    ssize_t length;
    ssize_t extra;
    unsigned int interruptions = 0U;
    if (lseek(descriptor, 0, SEEK_SET) != 0) {
        return false;
    }
    do {
        length = read(descriptor, buffer, sizeof(buffer));
        if (length >= 0 || errno != EINTR) {
            break;
        }
        interruptions++;
    } while (interruptions < 8U);
    if (length <= 0 || length == (ssize_t)sizeof(buffer)) {
        return false;
    }
    do {
        extra = read(descriptor, &overflow, sizeof(overflow));
    } while (extra < 0 && errno == EINTR);
    return extra == 0 && bpe_parse_events(buffer, (size_t)length, events);
}

static enum bpe_procs_match bpe_read_procs_exact(int descriptor, pid_t expected_pid) {
    uint8_t buffer[64];
    uint8_t overflow;
    ssize_t length;
    ssize_t extra;
    uint64_t parsed_pid = 0U;
    size_t index;
    unsigned int interruptions = 0U;

    if (expected_pid < 0 || lseek(descriptor, 0, SEEK_SET) != 0) {
        return BPE_PROCS_ERROR;
    }
    do {
        length = read(descriptor, buffer, sizeof(buffer));
        if (length >= 0 || errno != EINTR) {
            break;
        }
        interruptions++;
    } while (interruptions < 8U);
    if (length < 0) {
        return BPE_PROCS_ERROR;
    }
    if (length == (ssize_t)sizeof(buffer)) {
        errno = 0;
        return BPE_PROCS_MISMATCH;
    }
    if (length == 0) {
        errno = 0;
        return expected_pid == 0 ? BPE_PROCS_MATCH : BPE_PROCS_MISMATCH;
    }
    do {
        extra = read(descriptor, &overflow, sizeof(overflow));
    } while (extra < 0 && errno == EINTR);
    if (extra < 0) {
        return BPE_PROCS_ERROR;
    }
    if (extra != 0 || expected_pid == 0 || length < 2 || buffer[length - 1] != '\n' ||
        buffer[0] == '0') {
        errno = 0;
        return BPE_PROCS_MISMATCH;
    }
    for (index = 0U; index + 1U < (size_t)length; index++) {
        uint8_t digit = buffer[index];
        if (digit < '0' || digit > '9' ||
            parsed_pid > (uint64_t)INT_MAX / UINT64_C(10)) {
            errno = 0;
            return BPE_PROCS_MISMATCH;
        }
        parsed_pid = parsed_pid * UINT64_C(10) + (uint64_t)(digit - '0');
        if (parsed_pid > (uint64_t)INT_MAX) {
            errno = 0;
            return BPE_PROCS_MISMATCH;
        }
    }
    errno = 0;
    return parsed_pid == (uint64_t)expected_pid ? BPE_PROCS_MATCH
                                                 : BPE_PROCS_MISMATCH;
}

static bool bpe_write_cgroup_kill(int descriptor) {
    static const uint8_t kill_value = '1';
    ssize_t written;
    unsigned int interruptions = 0U;
    do {
        written = write(descriptor, &kill_value, sizeof(kill_value));
        if (written >= 0 || errno != EINTR) {
            break;
        }
        interruptions++;
    } while (interruptions < 8U);
    return written == (ssize_t)sizeof(kill_value);
}

static bool bpe_reset_signal_state(void) {
    struct sigaction action;
    sigset_t empty;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) != 0 || sigaction(SIGCHLD, &action, NULL) != 0 ||
        sigemptyset(&empty) != 0 || sigprocmask(SIG_SETMASK, &empty, NULL) != 0) {
        return false;
    }
    return true;
}

static bool bpe_install_seccomp(void) {
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(bpe_inert_seccomp_filter) /
                                sizeof(bpe_inert_seccomp_filter[0])),
        .filter = (struct sock_filter *)(uintptr_t)bpe_inert_seccomp_filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER) {
        return false;
    }
    return true;
}

static bool bpe_control_failed(short revents, struct bpe_runtime *runtime,
                               struct bpe_failure *failure, uint32_t stage) {
    if ((revents & POLLIN) != 0) {
        bpe_set_failure(failure, BPE_INERT_STAGE_PROTOCOL,
                        BPE_INERT_REASON_PROTOCOL_INPUT, 0);
        return true;
    }
    if ((revents & (POLLHUP | POLLERR)) != 0) {
        runtime->peer_open = false;
        bpe_set_failure(failure, BPE_INERT_STAGE_PROTOCOL,
                        BPE_INERT_REASON_PEER_CLOSED, 0);
        return true;
    }
    if ((revents & POLLNVAL) != 0) {
        runtime->control_usable = false;
        runtime->peer_open = false;
        bpe_set_failure(failure, stage, BPE_INERT_REASON_IO_FAILURE, EBADF);
        return true;
    }
    return false;
}

static bool bpe_control_quiet(struct bpe_runtime *runtime,
                              struct bpe_failure *failure, uint32_t stage) {
    struct pollfd descriptor = {
        .fd = BPE_INERT_CONTROL_FD,
        .events = POLLIN,
        .revents = 0,
    };
    unsigned int interruptions = 0U;
    int result;

    do {
        result = poll(&descriptor, 1U, 0);
        if (result >= 0 || errno != EINTR) {
            break;
        }
        interruptions++;
    } while (interruptions < 8U);
    if (result < 0) {
        bpe_set_failure(failure, stage, BPE_INERT_REASON_IO_FAILURE, errno);
        return false;
    }
    return result == 0 || !bpe_control_failed(descriptor.revents, runtime, failure, stage);
}

static int bpe_poll_until(struct pollfd *descriptors, nfds_t count, uint64_t deadline,
                          int maximum_ms) {
    int result;
    int timeout;
    do {
        timeout = bpe_deadline_poll_ms(deadline, maximum_ms);
        if (timeout == 0) {
            return 0;
        }
        result = poll(descriptors, count, timeout);
    } while (result < 0 && errno == EINTR);
    return result;
}

static void bpe_child_report_and_exit(int ready_fd, uint8_t status, int error_number)
    __attribute__((noreturn));

static void bpe_child_report_and_exit(int ready_fd, uint8_t status, int error_number) {
    uint8_t record[BPE_CHILD_RECORD_SIZE] = {'B', 'P', 'E', 'C', status, 0U, 0U, 0U};
    if (error_number >= 1 && error_number <= (int)BPE_INERT_MAX_ERRNO) {
        record[6] = (uint8_t)((unsigned int)error_number >> 8);
        record[7] = (uint8_t)error_number;
    }
    (void)syscall(SYS_write, ready_fd, record, sizeof(record));
    (void)syscall(SYS_close, ready_fd);
    (void)syscall(SYS_exit, status == 0U ? 0 : 125);
    __builtin_unreachable();
}

static void bpe_child_fixture(void) __attribute__((noreturn));

static void bpe_child_fixture(void) {
    int descriptor;
    for (descriptor = 0; descriptor < BPE_CHILD_READY_WRITE_FD; descriptor++) {
        if (syscall(SYS_close, descriptor) != 0) {
            bpe_child_report_and_exit(BPE_CHILD_READY_WRITE_FD, 1U, errno);
        }
    }
    if (syscall(SYS_close_range, (unsigned int)(BPE_CHILD_READY_WRITE_FD + 1), UINT_MAX,
                0U) != 0) {
        bpe_child_report_and_exit(BPE_CHILD_READY_WRITE_FD, 1U, errno);
    }
    {
        uint8_t ready[BPE_CHILD_RECORD_SIZE] = {'B', 'P', 'E', 'C', 0U, 0U, 0U, 0U};
        if (syscall(SYS_write, BPE_CHILD_READY_WRITE_FD, ready, sizeof(ready)) !=
            (long)sizeof(ready)) {
            (void)syscall(SYS_exit, 125);
            __builtin_unreachable();
        }
    }
    if (syscall(SYS_close, BPE_CHILD_READY_WRITE_FD) != 0) {
        (void)syscall(SYS_exit, 125);
        __builtin_unreachable();
    }
    for (;;) {
        (void)syscall(SYS_pause);
    }
}

static bool bpe_clone_fixture(struct bpe_runtime *runtime, struct bpe_failure *failure) {
    struct bpe_clone_args arguments;
    long clone_result;
    int pipe_fds[2] = {-1, -1};
    int pidfd = -1;
    memset(&arguments, 0, sizeof(arguments));
    if (pipe2(pipe_fds, O_CLOEXEC | O_NONBLOCK) != 0 ||
        pipe_fds[0] != BPE_CHILD_READY_READ_FD || pipe_fds[1] != BPE_CHILD_READY_WRITE_FD) {
        bpe_set_failure(failure, BPE_INERT_STAGE_FIXTURE_SETUP,
                        BPE_INERT_REASON_RESOURCE_EXHAUSTED, errno);
        if (pipe_fds[0] >= 0) {
            (void)close(pipe_fds[0]);
        }
        if (pipe_fds[1] >= 0) {
            (void)close(pipe_fds[1]);
        }
        return false;
    }
    runtime->ready_read_fd = pipe_fds[0];
    runtime->ready_write_fd = pipe_fds[1];
    arguments.flags = BPE_CLONE_FLAGS;
    arguments.pidfd = (uint64_t)(uintptr_t)&pidfd;
    arguments.exit_signal = (uint64_t)SIGCHLD;
    arguments.cgroup = (uint64_t)BPE_INERT_CGROUP_FD;
    clone_result = syscall(SYS_clone3, &arguments, sizeof(arguments));
    if (clone_result == 0) {
        bpe_child_fixture();
    }
    if (clone_result < 0) {
        int clone_errno = errno;
        uint32_t reason = BPE_INERT_REASON_CLONE3_REJECTED;
        if (clone_errno == ENOSYS) {
            reason = BPE_INERT_REASON_CLONE3_UNAVAILABLE;
        } else if (clone_errno == EAGAIN || clone_errno == ENOMEM || clone_errno == EMFILE ||
                   clone_errno == ENFILE) {
            reason = BPE_INERT_REASON_RESOURCE_EXHAUSTED;
        }
        bpe_set_failure(failure, BPE_INERT_STAGE_CLONE3, reason, clone_errno);
        return false;
    }
    runtime->child_pid = (pid_t)clone_result;
    runtime->child_created = true;
    runtime->pidfd = pidfd;
    runtime->achieved |= BPE_INERT_RESULT_CLONE3_INTO_CGROUP;
    {
        int pidfd_flags = fcntl(runtime->pidfd, F_GETFD);
        if (runtime->pidfd != BPE_EXPECTED_PIDFD || pidfd_flags < 0 ||
            (pidfd_flags & FD_CLOEXEC) == 0) {
            bpe_set_failure(failure, BPE_INERT_STAGE_CLONE3,
                            BPE_INERT_REASON_PIDFD_UNAVAILABLE,
                            pidfd_flags < 0 ? errno : 0);
            return false;
        }
    }
    runtime->achieved |= BPE_INERT_RESULT_PIDFD_CREATED;
    if (close(runtime->ready_write_fd) != 0) {
        bpe_set_failure(failure, BPE_INERT_STAGE_FIXTURE_SETUP,
                        BPE_INERT_REASON_IO_FAILURE, errno);
        return false;
    }
    runtime->ready_write_fd = -1;
    return true;
}

static bool bpe_wait_child_ready(struct bpe_runtime *runtime, uint64_t deadline,
                                 struct bpe_failure *failure) {
    struct pollfd descriptors[3];
    uint8_t record[BPE_CHILD_RECORD_SIZE];
    bool success_record_seen = false;
    ssize_t length;
    for (;;) {
        memset(descriptors, 0, sizeof(descriptors));
        descriptors[0].fd = BPE_INERT_CONTROL_FD;
        descriptors[0].events = POLLIN;
        descriptors[1].fd = runtime->ready_read_fd;
        descriptors[1].events = POLLIN;
        descriptors[2].fd = runtime->pidfd;
        descriptors[2].events = POLLIN;
        {
            int poll_result = bpe_poll_until(descriptors, 3U, deadline, INT_MAX);
            if (poll_result == 0) {
                bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_READY,
                                BPE_INERT_REASON_TIMEOUT, 0);
                return false;
            }
            if (poll_result < 0) {
                bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_READY,
                                BPE_INERT_REASON_IO_FAILURE, errno);
                return false;
            }
        }
        if (bpe_control_failed(descriptors[0].revents, runtime, failure,
                               BPE_INERT_STAGE_CHILD_READY)) {
            return false;
        }
        if ((descriptors[1].revents & (POLLIN | POLLHUP)) != 0) {
            length = read(runtime->ready_read_fd, record,
                          success_record_seen ? 1U : sizeof(record));
            if (success_record_seen) {
                if (length == 0) {
                    return true;
                }
                if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    continue;
                }
                bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_READY,
                                BPE_INERT_REASON_CHILD_SETUP_FAILED,
                                length < 0 ? errno : 0);
                return false;
            }
            if (length != (ssize_t)sizeof(record) || memcmp(record, "BPEC", 4U) != 0 ||
                record[5] != 0U ||
                (record[4] != 0U && record[4] != 1U)) {
                bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_READY,
                                BPE_INERT_REASON_CHILD_SETUP_FAILED,
                                length < 0 ? errno : 0);
                return false;
            }
            if (record[4] == 0U && (record[6] != 0U || record[7] != 0U)) {
                bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_READY,
                                BPE_INERT_REASON_CHILD_SETUP_FAILED, 0);
                return false;
            }
            if (record[4] != 0U) {
                int child_errno = ((int)record[6] << 8) | (int)record[7];
                bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_READY,
                                BPE_INERT_REASON_CHILD_SETUP_FAILED, child_errno);
                return false;
            }
            success_record_seen = true;
            continue;
        }
        if ((descriptors[1].revents & (POLLERR | POLLNVAL)) != 0 ||
            (descriptors[2].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
            bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_READY,
                            BPE_INERT_REASON_CHILD_SETUP_FAILED, 0);
            return false;
        }
    }
}

static bool bpe_wait_populated_one(struct bpe_runtime *runtime, uint64_t deadline,
                                   struct bpe_failure *failure) {
    struct bpe_events events;
    struct pollfd descriptors[3];
    for (;;) {
        if (!bpe_read_events(runtime->events_fd, &events)) {
            bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_READY,
                            BPE_INERT_REASON_IO_FAILURE, errno);
            return false;
        }
        if (events.populated == 1) {
            return true;
        }
        memset(descriptors, 0, sizeof(descriptors));
        descriptors[0].fd = BPE_INERT_CONTROL_FD;
        descriptors[0].events = POLLIN;
        descriptors[1].fd = runtime->events_fd;
        descriptors[1].events = POLLPRI | POLLERR;
        descriptors[2].fd = runtime->pidfd;
        descriptors[2].events = POLLIN;
        {
            int poll_result = bpe_poll_until(descriptors, 3U, deadline, INT_MAX);
            if (poll_result == 0) {
                bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_READY,
                                BPE_INERT_REASON_TIMEOUT, 0);
                return false;
            }
            if (poll_result < 0) {
                bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_READY,
                                BPE_INERT_REASON_IO_FAILURE, errno);
                return false;
            }
        }
        if (bpe_control_failed(descriptors[0].revents, runtime, failure,
                               BPE_INERT_STAGE_CHILD_READY)) {
            return false;
        }
        if ((descriptors[1].revents & POLLNVAL) != 0 ||
            (descriptors[2].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
            bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_READY,
                            BPE_INERT_REASON_CHILD_SETUP_FAILED, 0);
            return false;
        }
    }
}

static int bpe_pidfd_send_signal(int pidfd, int signal_number) {
    return (int)syscall(SYS_pidfd_send_signal, pidfd, signal_number, NULL, 0U);
}

static int bpe_waitid_pidfd(int pidfd, siginfo_t *information, int options) {
    memset(information, 0, sizeof(*information));
    return (int)syscall(SYS_waitid, BPE_P_PIDFD, pidfd, information, options, NULL);
}

static bool bpe_stop_and_observe(struct bpe_runtime *runtime, uint64_t deadline,
                                 struct bpe_failure *failure) {
    siginfo_t information;
    struct pollfd descriptors[2];
    if (bpe_pidfd_send_signal(runtime->pidfd, SIGSTOP) != 0) {
        bpe_set_failure(failure, BPE_INERT_STAGE_PIDFD_SIGNAL,
                        BPE_INERT_REASON_PIDFD_SIGNAL_FAILED, errno);
        return false;
    }
    runtime->achieved |= BPE_INERT_RESULT_PIDFD_STOP_SENT;
    for (;;) {
        if (bpe_waitid_pidfd(runtime->pidfd, &information,
                             WSTOPPED | WNOHANG | WNOWAIT) != 0) {
            bpe_set_failure(failure, BPE_INERT_STAGE_PIDFD_SIGNAL,
                            BPE_INERT_REASON_CHILD_OBSERVATION_FAILED, errno);
            return false;
        }
        if (information.si_pid != 0) {
            if (information.si_pid != runtime->child_pid || information.si_code != CLD_STOPPED ||
                information.si_status != SIGSTOP) {
                bpe_set_failure(failure, BPE_INERT_STAGE_PIDFD_SIGNAL,
                                BPE_INERT_REASON_CHILD_OBSERVATION_FAILED, 0);
                return false;
            }
            runtime->achieved |= BPE_INERT_RESULT_PIDFD_STOP_OBSERVED;
            return true;
        }
        memset(descriptors, 0, sizeof(descriptors));
        descriptors[0].fd = BPE_INERT_CONTROL_FD;
        descriptors[0].events = POLLIN;
        descriptors[1].fd = runtime->pidfd;
        descriptors[1].events = POLLIN;
        {
            int poll_result = bpe_poll_until(descriptors, 2U, deadline, 10);
            if (poll_result < 0) {
                bpe_set_failure(failure, BPE_INERT_STAGE_PIDFD_SIGNAL,
                                BPE_INERT_REASON_IO_FAILURE, errno);
                return false;
            }
            if (poll_result == 0 && bpe_deadline_poll_ms(deadline, 1) == 0) {
                bpe_set_failure(failure, BPE_INERT_STAGE_PIDFD_SIGNAL,
                                BPE_INERT_REASON_TIMEOUT, 0);
                return false;
            }
        }
        if (bpe_control_failed(descriptors[0].revents, runtime, failure,
                               BPE_INERT_STAGE_PIDFD_SIGNAL)) {
            return false;
        }
        if ((descriptors[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
            bpe_set_failure(failure, BPE_INERT_STAGE_PIDFD_SIGNAL,
                            BPE_INERT_REASON_CHILD_OBSERVATION_FAILED, 0);
            return false;
        }
    }
}

static bool bpe_observe_killed_and_empty(struct bpe_runtime *runtime, uint64_t deadline,
                                         siginfo_t *exit_information,
                                         struct bpe_failure *failure, bool monitor_control) {
    bool exit_seen = false;
    bool empty_seen = false;
    struct pollfd descriptors[3];
    while (!exit_seen || !empty_seen) {
        struct bpe_events events;
        siginfo_t information;
        if (!empty_seen) {
            if (!bpe_read_events(runtime->events_fd, &events)) {
                bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_OBSERVATION,
                                BPE_INERT_REASON_IO_FAILURE, errno);
                return false;
            }
            empty_seen = events.populated == 0;
        }
        if (!exit_seen) {
            if (bpe_waitid_pidfd(runtime->pidfd, &information,
                                 WEXITED | WNOHANG | WNOWAIT) != 0) {
                bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_OBSERVATION,
                                BPE_INERT_REASON_CHILD_OBSERVATION_FAILED, errno);
                return false;
            }
            if (information.si_pid != 0) {
                *exit_information = information;
                exit_seen = true;
            }
        }
        if (exit_seen && empty_seen) {
            return true;
        }
        memset(descriptors, 0, sizeof(descriptors));
        descriptors[0].fd = monitor_control ? BPE_INERT_CONTROL_FD : -1;
        descriptors[0].events = POLLIN;
        descriptors[1].fd = runtime->events_fd;
        descriptors[1].events = POLLPRI | POLLERR;
        descriptors[2].fd = runtime->pidfd;
        descriptors[2].events = POLLIN;
        {
            int poll_result = bpe_poll_until(descriptors, 3U, deadline, INT_MAX);
            if (poll_result == 0) {
                bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_OBSERVATION,
                                BPE_INERT_REASON_TIMEOUT, 0);
                return false;
            }
            if (poll_result < 0) {
                bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_OBSERVATION,
                                BPE_INERT_REASON_IO_FAILURE, errno);
                return false;
            }
        }
        if (monitor_control && bpe_control_failed(descriptors[0].revents, runtime, failure,
                                                  BPE_INERT_STAGE_CHILD_OBSERVATION)) {
            return false;
        }
        if ((descriptors[1].revents & POLLNVAL) != 0 ||
            (descriptors[2].revents & POLLNVAL) != 0) {
            bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_OBSERVATION,
                            BPE_INERT_REASON_IO_FAILURE, EBADF);
            return false;
        }
    }
    return false;
}

static bool bpe_reap_child(struct bpe_runtime *runtime, struct bpe_failure *failure) {
    siginfo_t information;
    if (bpe_waitid_pidfd(runtime->pidfd, &information, WEXITED) != 0 ||
        information.si_pid != runtime->child_pid) {
        bpe_set_failure(failure, BPE_INERT_STAGE_CHILD_REAP,
                        BPE_INERT_REASON_CHILD_REAP_FAILED, errno);
        return false;
    }
    runtime->child_reaped = true;
    runtime->achieved |= BPE_INERT_RESULT_CHILD_REAPED;
    return true;
}

static bool bpe_emergency_cleanup(struct bpe_runtime *runtime) {
    uint64_t deadline;
    struct bpe_failure ignored = {0U, 0U, 0};
    siginfo_t information;
    bool observed = false;
    bool empty = false;
    if (!runtime->child_created) {
        return true;
    }
    if (!bpe_deadline_after_ms(BPE_INERT_EMERGENCY_CLEANUP_MS, &deadline)) {
        return false;
    }
    if (!runtime->child_reaped && runtime->pidfd >= 0) {
        if (bpe_pidfd_send_signal(runtime->pidfd, SIGKILL) != 0 && errno != ESRCH) {
            /* cgroup.kill is still attempted below. */
        }
    }
    if (runtime->kill_fd >= 0) {
        (void)bpe_write_cgroup_kill(runtime->kill_fd);
    }
    if (!runtime->child_reaped && runtime->pidfd >= 0 && runtime->events_fd >= 0) {
        observed = bpe_observe_killed_and_empty(runtime, deadline, &information, &ignored,
                                                false);
        if (observed) {
            struct bpe_failure reap_failure = {0U, 0U, 0};
            if (!bpe_reap_child(runtime, &reap_failure)) {
                return false;
            }
        }
    }
    if (runtime->events_fd >= 0) {
        struct bpe_events events;
        empty = bpe_read_events(runtime->events_fd, &events) && events.populated == 0;
        if (empty) {
            runtime->achieved |= BPE_INERT_RESULT_CGROUP_EMPTY;
        }
    }
    return runtime->child_reaped && empty;
}

static bool bpe_close_descriptor(int *descriptor) {
    int original;
    if (*descriptor < 0) {
        return true;
    }
    original = *descriptor;
    *descriptor = -1;
    return close(original) == 0;
}

static bool bpe_close_owned(struct bpe_runtime *runtime) {
    bool ok = true;
    ok = bpe_close_descriptor(&runtime->ready_read_fd) && ok;
    ok = bpe_close_descriptor(&runtime->ready_write_fd) && ok;
    ok = bpe_close_descriptor(&runtime->pidfd) && ok;
    ok = bpe_close_descriptor(&runtime->events_fd) && ok;
    ok = bpe_close_descriptor(&runtime->kill_fd) && ok;
    ok = bpe_close_descriptor(&runtime->procs_fd) && ok;
    if (runtime->cgroup_usable) {
        runtime->cgroup_usable = false;
        if (close(BPE_INERT_CGROUP_FD) != 0) {
            ok = false;
        }
    }
    return ok;
}

int main(int argc, char **argv, char **environment) {
    struct bpe_runtime runtime = {
        .events_fd = -1,
        .kill_fd = -1,
        .procs_fd = -1,
        .ready_read_fd = -1,
        .ready_write_fd = -1,
        .pidfd = -1,
        .launcher_pid = getpid(),
        .child_pid = -1,
        .sequence = 0U,
        .achieved = 0U,
        .started_ns = 0U,
        .control_usable = false,
        .cgroup_usable = false,
        .peer_open = true,
        .child_created = false,
        .child_reaped = false,
    };
    struct bpe_failure failure = {0U, BPE_INERT_REASON_NONE, 0};
    struct bpe_events initial_events;
    siginfo_t exit_information;
    enum bpe_procs_match procs_match;
    uint64_t runtime_deadline;
    uint64_t final_elapsed_ns;
    bool terminal_cleanup_incomplete;
    int terminal_cleanup_errno;
    int exit_code;

    if (!bpe_monotonic_ns(&runtime.started_ns)) {
        return BPE_INERT_EXIT_INTERNAL;
    }
    if (argc != 1) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_STARTUP, BPE_INERT_REASON_BAD_ARGC, 0);
        goto fail;
    }
    if (argv == NULL || argv[0] == NULL || argv[1] != NULL || !bpe_exact_argv0(argv[0])) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_STARTUP, BPE_INERT_REASON_BAD_ARGV, 0);
        goto fail;
    }
    if (environment == NULL || environment[0] != NULL) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_STARTUP,
                        BPE_INERT_REASON_NONEMPTY_ENVIRONMENT, 0);
        goto fail;
    }
    if (!bpe_validate_startup_fds(&runtime, &failure) ||
        !bpe_open_cgroup_files(&runtime, &failure)) {
        goto fail;
    }
    if (!bpe_read_events(runtime.events_fd, &initial_events)) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_CGROUP_VALIDATION,
                        BPE_INERT_REASON_BAD_CGROUP_DESCRIPTOR, errno);
        goto fail;
    }
    procs_match = bpe_read_procs_exact(runtime.procs_fd, 0);
    if (procs_match == BPE_PROCS_ERROR) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_CGROUP_VALIDATION,
                        BPE_INERT_REASON_BAD_CGROUP_DESCRIPTOR, errno);
        goto fail;
    }
    if (initial_events.populated != 0 || procs_match != BPE_PROCS_MATCH) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_CGROUP_VALIDATION,
                        BPE_INERT_REASON_CGROUP_NOT_EMPTY, 0);
        goto fail;
    }
    if (!bpe_reset_signal_state() || !bpe_install_seccomp()) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_STARTUP, BPE_INERT_REASON_INTERNAL,
                        errno);
        goto fail;
    }
    if (!bpe_emit_frame(&runtime, BPE_INERT_FRAME_HELLO, BPE_INERT_STATUS_OK,
                        BPE_INERT_STAGE_STARTUP, BPE_INERT_REASON_NONE, 0U,
                        (uint64_t)runtime.launcher_pid, 0U)) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_PROTOCOL, BPE_INERT_REASON_IO_FAILURE,
                        errno);
        goto fail;
    }
    if (!bpe_deadline_after_ms(BPE_INERT_EMERGENCY_RUNTIME_MS, &runtime_deadline)) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_FIXTURE_SETUP, BPE_INERT_REASON_INTERNAL,
                        errno);
        goto fail;
    }
    if (!bpe_control_quiet(&runtime, &failure, BPE_INERT_STAGE_FIXTURE_SETUP)) {
        goto fail;
    }
    if (!bpe_clone_fixture(&runtime, &failure) ||
        !bpe_wait_child_ready(&runtime, runtime_deadline, &failure) ||
        !bpe_wait_populated_one(&runtime, runtime_deadline, &failure)) {
        goto fail;
    }
    procs_match = bpe_read_procs_exact(runtime.procs_fd, runtime.child_pid);
    if (procs_match != BPE_PROCS_MATCH) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_CHILD_READY,
                        procs_match == BPE_PROCS_ERROR ? BPE_INERT_REASON_IO_FAILURE
                                                       : BPE_INERT_REASON_CHILD_OBSERVATION_FAILED,
                        procs_match == BPE_PROCS_ERROR ? errno : 0);
        goto fail;
    }
    runtime.achieved |= BPE_INERT_RESULT_BUILTIN_NOEXEC;
    if (!bpe_control_quiet(&runtime, &failure, BPE_INERT_STAGE_CHILD_READY)) {
        goto fail;
    }
    if (!bpe_emit_frame(&runtime, BPE_INERT_FRAME_CHILD_READY, BPE_INERT_STATUS_OK,
                        BPE_INERT_STAGE_CHILD_READY, BPE_INERT_REASON_NONE, 0U,
                        (uint64_t)runtime.child_pid, BPE_CLONE_FLAGS)) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_PROTOCOL, BPE_INERT_REASON_IO_FAILURE,
                        errno);
        goto fail;
    }
    if (!bpe_stop_and_observe(&runtime, runtime_deadline, &failure)) {
        goto fail;
    }
    {
        struct bpe_events stopped_events;
        if (!bpe_read_events(runtime.events_fd, &stopped_events)) {
            bpe_set_failure(&failure, BPE_INERT_STAGE_PIDFD_SIGNAL,
                            BPE_INERT_REASON_IO_FAILURE, errno);
            goto fail;
        }
        procs_match = bpe_read_procs_exact(runtime.procs_fd, runtime.child_pid);
        if (procs_match == BPE_PROCS_ERROR) {
            bpe_set_failure(&failure, BPE_INERT_STAGE_PIDFD_SIGNAL,
                            BPE_INERT_REASON_IO_FAILURE, errno);
            goto fail;
        }
        if (stopped_events.populated != 1 || procs_match != BPE_PROCS_MATCH) {
            bpe_set_failure(&failure, BPE_INERT_STAGE_PIDFD_SIGNAL,
                            BPE_INERT_REASON_CHILD_OBSERVATION_FAILED, 0);
            goto fail;
        }
    }
    if (!bpe_control_quiet(&runtime, &failure, BPE_INERT_STAGE_PIDFD_SIGNAL)) {
        goto fail;
    }
    if (!bpe_emit_frame(&runtime, BPE_INERT_FRAME_CHILD_SIGNALED, BPE_INERT_STATUS_OK,
                        BPE_INERT_STAGE_PIDFD_SIGNAL, BPE_INERT_REASON_NONE, 0U,
                        (uint64_t)CLD_STOPPED, (uint64_t)SIGSTOP)) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_PROTOCOL, BPE_INERT_REASON_IO_FAILURE,
                        errno);
        goto fail;
    }
    if (!bpe_control_quiet(&runtime, &failure, BPE_INERT_STAGE_CGROUP_KILL)) {
        goto fail;
    }
    if (!bpe_write_cgroup_kill(runtime.kill_fd)) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_CGROUP_KILL,
                        BPE_INERT_REASON_CGROUP_KILL_FAILED, errno);
        goto fail;
    }
    runtime.achieved |= BPE_INERT_RESULT_LIVE_CGROUP_KILL;
    if (!bpe_observe_killed_and_empty(&runtime, runtime_deadline, &exit_information,
                                      &failure, true)) {
        goto fail;
    }
    if (exit_information.si_pid != runtime.child_pid ||
        exit_information.si_code != CLD_KILLED || exit_information.si_status != SIGKILL) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_CHILD_OBSERVATION,
                        BPE_INERT_REASON_CHILD_OBSERVATION_FAILED, 0);
        goto fail;
    }
    runtime.achieved |= BPE_INERT_RESULT_PIDFD_EXIT_OBSERVED;
    runtime.achieved |= BPE_INERT_RESULT_CGROUP_EMPTY;
    if (!bpe_control_quiet(&runtime, &failure,
                           BPE_INERT_STAGE_CHILD_OBSERVATION)) {
        goto fail;
    }
    if (!bpe_emit_frame(&runtime, BPE_INERT_FRAME_CHILD_OBSERVED, BPE_INERT_STATUS_OK,
                        BPE_INERT_STAGE_CHILD_OBSERVATION, BPE_INERT_REASON_NONE, 0U,
                        (uint64_t)CLD_KILLED, (uint64_t)SIGKILL) ||
        !bpe_reap_child(&runtime, &failure)) {
        if (failure.reason == BPE_INERT_REASON_NONE) {
            bpe_set_failure(&failure, BPE_INERT_STAGE_PROTOCOL,
                            BPE_INERT_REASON_IO_FAILURE, errno);
        }
        goto fail;
    }
    if (runtime.achieved != BPE_INERT_ACHIEVED_MASK) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_CLEANUP, BPE_INERT_REASON_INTERNAL, 0);
        goto fail;
    }
    final_elapsed_ns = bpe_elapsed_ns(&runtime);
    if (final_elapsed_ns == 0U) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_CLEANUP,
                        BPE_INERT_REASON_INTERNAL, 0);
        goto fail;
    }
    if (!bpe_control_quiet(&runtime, &failure, BPE_INERT_STAGE_CLEANUP)) {
        goto fail;
    }
    if (!bpe_close_owned(&runtime)) {
        bpe_set_failure(&failure, BPE_INERT_STAGE_CLEANUP,
                        BPE_INERT_REASON_CLEANUP_INCOMPLETE, errno);
        goto fail;
    }
    if (!bpe_emit_frame(&runtime, BPE_INERT_FRAME_FINAL, BPE_INERT_STATUS_OK,
                        BPE_INERT_STAGE_CLEANUP, BPE_INERT_REASON_NONE, 0U,
                        runtime.achieved, final_elapsed_ns)) {
        return BPE_INERT_EXIT_PROTOCOL;
    }
    return BPE_INERT_EXIT_OK;

fail:
    terminal_cleanup_incomplete = false;
    terminal_cleanup_errno = 0;
    if (runtime.child_created && !runtime.child_reaped && !bpe_emergency_cleanup(&runtime)) {
        terminal_cleanup_incomplete = true;
    }
    if (!bpe_close_owned(&runtime)) {
        terminal_cleanup_incomplete = true;
        terminal_cleanup_errno = errno;
    }
    if (terminal_cleanup_incomplete) {
        /* Cleanup safety has precedence over the earlier diagnostic reason. */
        failure.stage = BPE_INERT_STAGE_CLEANUP;
        failure.reason = BPE_INERT_REASON_CLEANUP_INCOMPLETE;
        failure.error_number = terminal_cleanup_errno;
    }
    if (failure.reason == BPE_INERT_REASON_NONE) {
        failure.stage = BPE_INERT_STAGE_STARTUP;
        failure.reason = BPE_INERT_REASON_INTERNAL;
        failure.error_number = 0;
    }
    exit_code = bpe_exit_for_reason(failure.reason);
    if (runtime.control_usable && runtime.peer_open) {
        if (!bpe_emit_frame(&runtime, BPE_INERT_FRAME_ERROR, BPE_INERT_STATUS_FAILED,
                            failure.stage, failure.reason,
                            bpe_wire_errno(failure.error_number), runtime.achieved, 0U) &&
            exit_code != BPE_INERT_EXIT_CLEANUP) {
            exit_code = BPE_INERT_EXIT_PROTOCOL;
        }
    }
    return exit_code;
}
