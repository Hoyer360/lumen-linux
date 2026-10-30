/* Linux x86_64 backend for the unchanged, allow-listed nm_cpuinfo core.
 * CPU group/bit maps to Linux CPU number group*64+bit. Only this disposable
 * process's affinity changes; the complete original mask is restored. */
#define _GNU_SOURCE
#include <cpuid.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "nm_cpuinfo.h"

typedef struct { cpu_set_t original; int restoring; } linux_ctx;
static void l_cpuid(void *ctx, uint32_t leaf, uint32_t sub, nm_regs *r) {
    (void)ctx;
    __cpuid_count(leaf, sub, r->a, r->b, r->c, r->d);
}
static int l_xgetbv(void *ctx, uint32_t index, uint64_t *out) {
    uint32_t a, d;
    (void)ctx;
    __asm__ volatile ("xgetbv" : "=a"(a), "=d"(d) : "c"(index));
    *out = ((uint64_t)d << 32) | a;
    return 0;
}
static int l_groups(void *context, nm_group *out, int max) {
    linux_ctx *ctx = context;
    int count = 0;
    if (sched_getaffinity(0, sizeof(ctx->original), &ctx->original)) return -1;
    for (unsigned group = 0; group < CPU_SETSIZE / 64; group++) {
        uint64_t mask = 0;
        unsigned active = 0;
        for (unsigned bit = 0; bit < 64; bit++) {
            if (CPU_ISSET(group * 64 + bit, &ctx->original)) {
                mask |= 1ull << bit;
                active++;
            }
        }
        if (active) {
            if (count < max) {
                out[count].group = (uint16_t)group;
                out[count].mask = mask;
                out[count].active = (uint8_t)active;
            }
            count++;
        }
    }
    return count ? count : -1;
}
static int l_get_aff(void *context, nm_affinity *out) {
    linux_ctx *ctx = context;
    cpu_set_t current;
    if (sched_getaffinity(0, sizeof(current), &current)) return -1;
    if (!CPU_EQUAL(&current, &ctx->original)) return -1;
    /* Reserved token, never a real group; preserves a multi-group Linux mask. */
    out->group = UINT16_MAX;
    out->mask = 0;
    return 0;
}
static int l_set_aff(void *context, const nm_affinity *aff) {
    linux_ctx *ctx = context;
    cpu_set_t mask;
    if (aff->group == UINT16_MAX && aff->mask == 0)
        return sched_setaffinity(0, sizeof(ctx->original), &ctx->original);
    CPU_ZERO(&mask);
    for (unsigned bit = 0; bit < 64; bit++) {
        unsigned cpu = aff->group * 64u + bit;
        if ((aff->mask >> bit) & 1) {
            if (cpu >= CPU_SETSIZE || !CPU_ISSET(cpu, &ctx->original)) return -1;
            CPU_SET(cpu, &mask);
        }
    }
    if (sched_setaffinity(0, sizeof(mask), &mask)) return -1;
    sched_yield();
    return 0;
}
static int l_where(void *context, nm_affinity *out) {
    int cpu = sched_getcpu();
    (void)context;
    if (cpu < 0 || cpu >= CPU_SETSIZE) return -1;
    out->group = (uint16_t)(cpu / 64);
    out->mask = 1ull << (cpu % 64);
    return 0;
}
static uint64_t l_now(void *context) {
    struct timespec ts;
    (void)context;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
int main(int argc, char **argv) {
    static char data[NM_OUT_CAP];
    linux_ctx ctx;
    nm_out out = {data, sizeof(data), 0, 0};
    nm_backend backend = {&ctx, l_cpuid, l_xgetbv, l_groups, l_get_aff, l_set_aff, l_now, l_where};
    (void)argv;
    if (!nm_args_ok(argc)) return 2;
    memset(&ctx, 0, sizeof(ctx));
    alarm(5); /* Last-resort process timeout, also enforced by the Python owner. */
    if (nm_collect(&backend, &out, NM_DEFAULT_BUDGET_MS)) return 3;
    if (fwrite(out.buf, 1, out.len, stdout) != out.len || putchar('\n') == EOF) return 4;
    return 0;
}
