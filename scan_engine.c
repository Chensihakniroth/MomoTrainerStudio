/*
 * scan_engine.c — MomoTrainerStudio C scan engine v2
 *
 * Compile:
 *   gcc -shared -O2 -march=native -o scan_engine.dll scan_engine.c -lkernel32
 *
 * All numeric types: uint8/16/32/64, int8/16/32/64, float, double
 * Both fast-scan (aligned stride) and full-scan (every byte offset)
 * Multi-threaded with work-stealing (InterlockedIncrement per page)
 *
 * The CE hot-path: ReadProcessMemory -> typed compare loop -> results
 * No Python boundary, no intermediate copies, no numpy, just raw x86.
 */

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Result struct ──────────────────────────────────────────────── */
typedef struct {
    uint64_t addr;
    uint32_t value_lo;   /* low 32 bits (or full for 32-bit types) */
    uint32_t value_hi;   /* high 32 bits (for 64-bit types); 0 otherwise */
} ScanResult;

/* For the Python wrapper: expose addr + value as a single uint64 for
 * small types, and addr + two uint32s for 64-bit. */
typedef struct {
    uint64_t addr;
    uint32_t value;
} ScanResult32;

/* ── Compile-time knobs ──────────────────────────────────────────── */
#define CHUNK_SIZE    (64 * 1024)
#define MAX_THREADS   16
#define MAX_RESULTS   (10 * 1024 * 1024)  /* 10M hits cap */

/* ── Compare-mode enum (mirrors Python memory_scanner.py) ─────── */
typedef enum {
    CMP_EXACT = 0,
    CMP_GREATER = 1,
    CMP_LESS    = 2,
    CMP_CHANGED = 3,
    CMP_UNCHANGED = 4,
    CMP_INCREASED = 5,
    CMP_DECREASED = 6,
    CMP_BETWEEN   = 7,
} CompareMode;

/* ── Worker context ─────────────────────────────────────────────── */
typedef struct {
    HANDLE        hProcess;
    uint64_t     *pages;
    int          *page_sizes;
    int           n_pages;
    int           nlen;          /* element size in bytes: 1,2,4,8 */
    int           stepsize;      /* stride: nlen (fast) or 1 (full) */
    CompareMode   mode;          /* comparison operator */
    int           nthreads;

    /* Two-needle support (exact value + high bound for BETWEEN mode) */
    uint32_t      needle_lo;
    uint32_t      needle_hi;     /* only used for uint64 / BETWEEN */

    volatile LONG *next_page;
    ScanResult   *results;
    int           max_results;
    volatile LONG *result_count;
} WorkerCtx;

/* ── Worker thread ─────────────────────────────────────────────── */
static DWORD WINAPI scan_worker(LPVOID param)
{
    WorkerCtx *c = (WorkerCtx *)param;
    int nlen = c->nlen;
    int step = c->stepsize;
    uint32_t needle_lo = c->needle_lo;
    uint32_t needle_hi = c->needle_hi;

    /* Aligned buffer for RPM — uint64 so any type can read from it */
    uint8_t *buf = (uint8_t *)malloc(CHUNK_SIZE + 16);
    if (!buf) return 0;
    uint8_t *aligned_buf = (uint8_t *)((((uintptr_t)buf + 15) >> 4) << 4);

    SIZE_T bytes_read_sz;

    while (1) {
        LONG pg_idx = InterlockedIncrement(c->next_page) - 1;
        if (pg_idx >= c->n_pages) break;

        uint64_t base  = c->pages[pg_idx];
        int      psize = c->page_sizes[pg_idx];
        uint64_t offset = 0;

        while (offset < (uint64_t)psize) {
            DWORD cs = (DWORD)((psize - (DWORD)offset) < CHUNK_SIZE
                               ? (psize - (DWORD)offset) : CHUNK_SIZE);
            uint64_t addr = base + offset;

            if (!ReadProcessMemory(c->hProcess, (LPCVOID)addr,
                                   aligned_buf, cs, &bytes_read_sz)) {
                break;
            }
            if (bytes_read_sz < (SIZE_T)nlen) break;

            /* ── Type-specific compare loop ────────────────────────────── */
            /* Each branch handles a specific dtype. The compiler should
             * hoist the type-check out of the inner loop for fast-scan
             * (step == nlen), generating a tight x86 compare loop. */

            if (nlen == 1) {
                /* ── uint8 / int8 ─────────────────────────────────── */
                for (DWORD i = 0; i + 1 <= bytes_read_sz; i++) {
                    uint8_t v = aligned_buf[i];
                    int match = 0;
                    switch (c->mode) {
                        case CMP_EXACT:      match = (v == needle_lo); break;
                        case CMP_GREATER:    match = ((int8_t)v >  (int8_t)needle_lo); break;
                        case CMP_LESS:       match = ((int8_t)v <  (int8_t)needle_lo); break;
                        case CMP_INCREASED:   /* requires prev-value store — skip in C */ break;
                        case CMP_DECREASED:   /* requires prev-value store — skip in C */ break;
                        case CMP_CHANGED:     /* requires prev-value store — skip in C */ break;
                        case CMP_UNCHANGED:   /* requires prev-value store — skip in C */ break;
                        default:              match = 0;
                    }
                    if (match) {
                        LONG slot = InterlockedIncrement(c->result_count);
                        if (slot <= c->max_results) {
                            c->results[slot - 1].addr    = addr + i;
                            c->results[slot - 1].value_lo = v;
                            c->results[slot - 1].value_hi = 0;
                        }
                    }
                }
            } else if (nlen == 2) {
                /* ── uint16 / int16 ───────────────────────────────── */
                /* Step by 2, check every aligned offset */
                DWORD max_i = (DWORD)(bytes_read_sz & ~(DWORD)1); /* floor to even */
                for (DWORD i = 0; i < max_i; i += 2) {
                    uint16_t v = *(uint16_t *)(aligned_buf + i);
                    int match = 0;
                    switch (c->mode) {
                        case CMP_EXACT:   match = (v == needle_lo); break;
                        case CMP_GREATER: match = ((int16_t)v > (int16_t)needle_lo); break;
                        case CMP_LESS:    match = ((int16_t)v < (int16_t)needle_lo); break;
                        default:          match = 0;
                    }
                    if (match) {
                        LONG slot = InterlockedIncrement(c->result_count);
                        if (slot <= c->max_results) {
                            c->results[slot - 1].addr    = addr + i;
                            c->results[slot - 1].value_lo = v;
                            c->results[slot - 1].value_hi = 0;
                        }
                    }
                }
            } else if (nlen == 4) {
                /* ── uint32 / int32 / float ───────────────────────── */
                DWORD nvals = (DWORD)(bytes_read_sz >> 2);  /* bytes_read_sz / 4 */
                DWORD stride = (step == 1) ? 1 : 4;          /* full-scan=1, fast=4 */

                if (stride == 4) {
                    /* Fast path: aligned uint32, no scalar overhead */
                    uint32_t *p = (uint32_t *)aligned_buf;
                    for (DWORD i = 0; i < nvals; i++) {
                        uint32_t v = p[i];
                        int match = 0;
                        switch (c->mode) {
                            case CMP_EXACT:      match = (v == needle_lo); break;
                            case CMP_GREATER:    match = ((int32_t)v > (int32_t)needle_lo); break;
                            case CMP_LESS:       match = ((int32_t)v < (int32_t)needle_lo); break;
                            case CMP_BETWEEN:    match = (v >= needle_lo && v <= needle_hi); break;
                            default:             match = 0;
                        }
                        if (match) {
                            LONG slot = InterlockedIncrement(c->result_count);
                            if (slot <= c->max_results) {
                                c->results[slot - 1].addr    = addr + i * 4;
                                c->results[slot - 1].value_lo = v;
                                c->results[slot - 1].value_hi = 0;
                            }
                        }
                    }
                } else {
                    /* Full path: step by 1 byte, check every offset */
                    for (DWORD i = 0; i + 3 < bytes_read_sz; i++) {
                        uint32_t v = *(uint32_t *)(aligned_buf + i);
                        int match = 0;
                        switch (c->mode) {
                            case CMP_EXACT: match = (v == needle_lo); break;
                            default:        match = 0;
                        }
                        if (match) {
                            LONG slot = InterlockedIncrement(c->result_count);
                            if (slot <= c->max_results) {
                                c->results[slot - 1].addr    = addr + i;
                                c->results[slot - 1].value_lo = v;
                                c->results[slot - 1].value_hi = 0;
                            }
                        }
                    }
                }
            } else if (nlen == 8) {
                /* ── uint64 / int64 / double ────────────────────────── */
                DWORD nvals = (DWORD)(bytes_read_sz >> 3);  /* / 8 */
                DWORD stride = (step == 1) ? 1 : 8;

                if (stride == 8) {
                    /* Fast path: step by 8 */
                    for (DWORD i = 0; i < nvals; i++) {
                        uint64_t v64 = *(uint64_t *)(aligned_buf + i * 8);
                        uint32_t v_lo = (uint32_t)(v64 & 0xFFFFFFFF);
                        uint32_t v_hi = (uint32_t)(v64 >> 32);
                        int match = 0;
                        switch (c->mode) {
                            case CMP_EXACT:   match = (v_lo == needle_lo && v_hi == needle_hi); break;
                            case CMP_GREATER: match = (v64 > ((uint64_t)needle_hi << 32 | needle_lo)); break;
                            case CMP_LESS:    match = (v64 < ((uint64_t)needle_hi << 32 | needle_lo)); break;
                            default:          match = 0;
                        }
                        if (match) {
                            LONG slot = InterlockedIncrement(c->result_count);
                            if (slot <= c->max_results) {
                                c->results[slot - 1].addr    = addr + i * 8;
                                c->results[slot - 1].value_lo = v_lo;
                                c->results[slot - 1].value_hi = v_hi;
                            }
                        }
                    }
                } else {
                    /* Full path: step by 1, check every offset */
                    for (DWORD i = 0; i + 7 < bytes_read_sz; i++) {
                        uint64_t v64 = *(uint64_t *)(aligned_buf + i);
                        uint32_t v_lo = (uint32_t)(v64 & 0xFFFFFFFF);
                        uint32_t v_hi = (uint32_t)(v64 >> 32);
                        int match = 0;
                        switch (c->mode) {
                            case CMP_EXACT: match = (v_lo == needle_lo && v_hi == needle_hi); break;
                            default:        match = 0;
                        }
                        if (match) {
                            LONG slot = InterlockedIncrement(c->result_count);
                            if (slot <= c->max_results) {
                                c->results[slot - 1].addr    = addr + i;
                                c->results[slot - 1].value_lo = v_lo;
                                c->results[slot - 1].value_hi = v_hi;
                            }
                        }
                    }
                }
            }

            offset += (uint64_t)bytes_read_sz;
        }
    }

    free(buf);
    return 0;
}

/* ── Unified public API ─────────────────────────────────────────── */

/*
 * c_scan
 *
 * Single unified scan function for all numeric types.
 * Works for both fast-scan (aligned, step=nlen) and full-scan (step=1).
 *
 * Args:
 *   hProcess      Windows HANDLE from OpenProcess
 *   page_addrs    array of uint64 base addresses  [n_pages]
 *   page_sizes    array of int sizes             [n_pages]
 *   n_pages       number of memory regions
 *   nlen          element size: 1/2/4/8 bytes
 *   stepsize      scan stride: nlen (fast_scan) or 1 (full_scan)
 *   needle_lo     low 32 bits of search value (or full value for 32-bit types)
 *   needle_hi     high 32 bits (only for 64-bit types; 0 otherwise)
 *   nthreads      1-16 worker threads
 *   results       pre-allocated output buffer
 *   max_results   capacity of results buffer
 *
 * Returns: number of hits found (0..max_results), or -1 on error.
 */
__declspec(dllexport)
int c_scan(HANDLE hProcess,
           uint64_t *page_addrs,
           int      *page_sizes,
           int       n_pages,
           int       nlen,
           int       stepsize,
           uint32_t  needle_lo,
           uint32_t  needle_hi,
           int       nthreads,
           ScanResult *results,
           int       max_results)
{
    if (!hProcess || n_pages <= 0 || nthreads <= 0 || !results)
        return -1;
    if (max_results <= 0) return 0;

    if (nthreads > MAX_THREADS) nthreads = MAX_THREADS;
    if (nthreads > n_pages)    nthreads = n_pages;

    volatile LONG next_page     = 0;
    volatile LONG result_count  = 0;

    HANDLE   threads[MAX_THREADS];
    WorkerCtx ctxs[MAX_THREADS];
    DWORD    tids[MAX_THREADS];

    for (int t = 0; t < nthreads; t++) {
        ctxs[t].hProcess     = hProcess;
        ctxs[t].pages       = page_addrs;
        ctxs[t].page_sizes  = page_sizes;
        ctxs[t].n_pages     = n_pages;
        ctxs[t].nlen        = nlen;
        ctxs[t].stepsize    = stepsize;
        ctxs[t].needle_lo   = needle_lo;
        ctxs[t].needle_hi   = needle_hi;
        ctxs[t].nthreads    = nthreads;
        ctxs[t].next_page   = &next_page;
        ctxs[t].results     = results;
        ctxs[t].max_results = max_results;
        ctxs[t].result_count = &result_count;
        ctxs[t].mode        = CMP_EXACT;  /* C engine handles EXACT for now */

        threads[t] = CreateThread(NULL, 0, scan_worker, &ctxs[t], 0, &tids[t]);
    }

    WaitForMultipleObjects(nthreads, threads, TRUE, INFINITE);

    for (int t = 0; t < nthreads; t++)
        CloseHandle(threads[t]);

    LONG total = (LONG)result_count;
    return (int)(total > max_results ? max_results : total);
}

/* ── Typed wrappers (convenience, all call c_scan internally) ───── */

/*
 * For float: needle_bits = IEEE 754 bit pattern of the float
 * For double: needle_lo = low 32 bits, needle_hi = high 32 bits
 */
__declspec(dllexport)
int scan_uint8(HANDLE h, uint64_t *addrs, int *sizes, int n,
               uint8_t needle, int nthreads, ScanResult *r, int max_r)
{
    return c_scan(h, addrs, sizes, n, 1, 1,
                  needle, 0, nthreads, r, max_r);
}

__declspec(dllexport)
int scan_uint16(HANDLE h, uint64_t *addrs, int *sizes, int n,
                uint16_t needle, int nthreads, ScanResult *r, int max_r)
{
    return c_scan(h, addrs, sizes, n, 2, 2,
                  needle, 0, nthreads, r, max_r);
}

__declspec(dllexport)
int scan_uint32(HANDLE h, uint64_t *addrs, int *sizes, int n,
                uint32_t needle, int nthreads, ScanResult *r, int max_r)
{
    return c_scan(h, addrs, sizes, n, 4, 4,
                  needle, 0, nthreads, r, max_r);
}

__declspec(dllexport)
int scan_uint64(HANDLE h, uint64_t *addrs, int *sizes, int n,
                uint32_t needle_lo, uint32_t needle_hi,
                int nthreads, ScanResult *r, int max_r)
{
    return c_scan(h, addrs, sizes, n, 8, 8,
                  needle_lo, needle_hi, nthreads, r, max_r);
}

/* fast_scan=False (full scan): step = 1 */
__declspec(dllexport)
int scan_uint8_full(HANDLE h, uint64_t *addrs, int *sizes, int n,
                   uint8_t needle, int nthreads, ScanResult *r, int max_r)
{
    return c_scan(h, addrs, sizes, n, 1, 1,
                  needle, 0, nthreads, r, max_r);
}

__declspec(dllexport)
int scan_uint16_full(HANDLE h, uint64_t *addrs, int *sizes, int n,
                     uint16_t needle, int nthreads, ScanResult *r, int max_r)
{
    return c_scan(h, addrs, sizes, n, 2, 1,  /* nlen=2, step=1 */
                  needle, 0, nthreads, r, max_r);
}

__declspec(dllexport)
int scan_uint32_full(HANDLE h, uint64_t *addrs, int *sizes, int n,
                     uint32_t needle, int nthreads, ScanResult *r, int max_r)
{
    return c_scan(h, addrs, sizes, n, 4, 1,  /* nlen=4, step=1 */
                  needle, 0, nthreads, r, max_r);
}

__declspec(dllexport)
int scan_uint64_full(HANDLE h, uint64_t *addrs, int *sizes, int n,
                     uint32_t needle_lo, uint32_t needle_hi,
                     int nthreads, ScanResult *r, int max_r)
{
    return c_scan(h, addrs, sizes, n, 8, 1,
                  needle_lo, needle_hi, nthreads, r, max_r);
}

/* float32: needle_bits = bit pattern of the float */
__declspec(dllexport)
int scan_float32(HANDLE h, uint64_t *addrs, int *sizes, int n,
                 uint32_t needle_bits, int nthreads, ScanResult *r, int max_r)
{
    return c_scan(h, addrs, sizes, n, 4, 4,
                  needle_bits, 0, nthreads, r, max_r);
}

__declspec(dllexport)
int scan_float32_full(HANDLE h, uint64_t *addrs, int *sizes, int n,
                      uint32_t needle_bits, int nthreads, ScanResult *r, int max_r)
{
    return c_scan(h, addrs, sizes, n, 4, 1,
                  needle_bits, 0, nthreads, r, max_r);
}

/* double: needle_lo = low 32 bits, needle_hi = high 32 bits */
__declspec(dllexport)
int scan_double(HANDLE h, uint64_t *addrs, int *sizes, int n,
                uint32_t needle_lo, uint32_t needle_hi,
                int nthreads, ScanResult *r, int max_r)
{
    return c_scan(h, addrs, sizes, n, 8, 8,
                  needle_lo, needle_hi, nthreads, r, max_r);
}

/* ── DLL entry ───────────────────────────────────────────────────── */
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r)
{
    (void)h; (void)r;
    return TRUE;
}
