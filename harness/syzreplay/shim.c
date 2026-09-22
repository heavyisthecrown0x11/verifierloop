// syz-replay shim — turn a syzkaller corpus program into REAL verifier-log output.
//
// syzkaller drives coverage-guided fuzzing but never emits the verifier's
// decision + register-state (that lives in the caller's log_buf at log_level=2).
// `syz-prog2c` renders a corpus program as C that calls `syscall(__NR_bpf, ...)`
// directly. We compile that C with `-Dsyscall=vl_syscall` so every syscall goes
// through this wrapper, which:
//
//   * for BPF_PROG_LOAD: copies the attr, injects log_level=2 + a log buffer,
//     performs the real load, and prints the block in the harness native format
//     (===PROG / RESULT / ---LOG--- <verbatim> / ---END---);
//   * for everything else: passes through untouched.
//
// Result: the programs are syzkaller's, the verifier log is real, and the output
// is the exact native format the existing VerifierLogParser already consumes.
// Nothing about the program is altered — only the log-capture fields are set.

#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

// Label for this replay unit (set at compile time: -DVL_PROG_LABEL=\"...\").
#ifndef VL_PROG_LABEL
#define VL_PROG_LABEL "syzprog"
#endif

static char vl_log[128 * 1024];
static int vl_call_idx;

static uint64_t vl_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// Intercepts BPF_PROG_LOAD to capture the verifier log; passes everything else on.
long vl_syscall(long nr, ...) {
    va_list ap;
    va_start(ap, nr);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);

    if (nr != __NR_bpf || (int)a1 != BPF_PROG_LOAD || a2 == 0) {
        return syscall(nr, a1, a2, a3, a4, a5, a6);
    }

    // Copy the caller's attr into a full, zeroed union so trailing bytes stay 0,
    // then add ONLY the log-capture fields.
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    size_t n = (size_t)a3;
    if (n > sizeof(attr))
        n = sizeof(attr);
    memcpy(&attr, (const void *)a2, n);

    vl_log[0] = '\0';
    attr.log_level = 2;
    attr.log_size = sizeof(vl_log);
    attr.log_buf = (uint64_t)(unsigned long)vl_log;

    uint64_t t0 = vl_now_ns();
    long fd = syscall(__NR_bpf, BPF_PROG_LOAD, (long)&attr, (long)sizeof(attr), 0, 0, 0);
    int e = errno;
    uint64_t dt = vl_now_ns() - t0;

    printf("===PROG %s#%d type=%u ===\n", VL_PROG_LABEL, vl_call_idx++,
           (unsigned)attr.prog_type);
    printf("RESULT decision=%s fd=%ld errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);
    printf("---LOG---\n%s\n---END---\n", vl_log);
    fflush(stdout);

    // Hand the caller the real fd (or -1) so the rest of the program behaves
    // exactly as syzkaller intended (map/prog fd chains stay intact).
    if (fd < 0)
        errno = e;
    return fd;
}
