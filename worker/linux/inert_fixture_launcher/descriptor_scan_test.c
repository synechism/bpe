/* Keep the production scanner in the test's translation unit without exporting it. */
#define main bpe_inert_fixture_launcher_program_main
#include "launcher.c"
#undef main

#include <sys/resource.h>

int main(void) {
    struct bpe_failure failure = {0U, BPE_INERT_REASON_NONE, 0};
    struct rlimit original_limit;
    struct rlimit lowered_limit;
    int descriptor;
    int staging_fd;
    int high_fd;
    int sockets[2];
    uint8_t inbound = UINT8_C(0x78);
    struct bpe_runtime runtime = {
        .control_usable = false,
        .peer_open = true,
    };

    if (getrlimit(RLIMIT_NOFILE, &original_limit) != 0 || original_limit.rlim_cur < 32U) {
        return 1;
    }
    for (descriptor = 3; descriptor < 4096; descriptor++) {
        (void)close(descriptor);
    }
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) != 0 ||
        sockets[0] != BPE_INERT_CONTROL_FD || sockets[1] != BPE_INERT_CGROUP_FD) {
        return 10;
    }
    if (send(sockets[1], &inbound, sizeof(inbound), MSG_NOSIGNAL) !=
        (ssize_t)sizeof(inbound)) {
        return 11;
    }
    if (bpe_validate_control_fd(&runtime)) {
        return 12;
    }
    if (close(sockets[0]) != 0) {
        return 13;
    }
    if (recv(sockets[1], &inbound, sizeof(inbound), 0) != 0) {
        return 14;
    }
    if (close(sockets[1]) != 0) {
        return 15;
    }
    if (open("/dev/null", O_RDONLY | O_CLOEXEC) != 3 ||
        open("/dev/null", O_RDONLY | O_CLOEXEC) != 4) {
        return 2;
    }
    if (!bpe_validate_no_extra_fds(&failure) ||
        failure.reason != BPE_INERT_REASON_NONE) {
        return 3;
    }
    staging_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (staging_fd != 5) {
        return 4;
    }
    high_fd = fcntl(staging_fd, F_DUPFD_CLOEXEC, 16);
    if (high_fd < 16 || close(staging_fd) != 0) {
        return 5;
    }

    lowered_limit = original_limit;
    lowered_limit.rlim_cur = 8U;
    if (setrlimit(RLIMIT_NOFILE, &lowered_limit) != 0) {
        return 6;
    }

    if (bpe_validate_no_extra_fds(&failure)) {
        return 7;
    }
    if (failure.stage != BPE_INERT_STAGE_DESCRIPTOR_VALIDATION ||
        failure.reason != BPE_INERT_REASON_BAD_DESCRIPTOR_LAYOUT) {
        return 8;
    }
    if (fcntl(high_fd, F_GETFD) < 0) {
        return 9;
    }
    return 0;
}
