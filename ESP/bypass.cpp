/**
 * ============================================================================
 * iOS PUBG str_cmp17470 Bypass & Hooking Framework (Minimal Edition)
 * ============================================================================
 * 
 * Analiz Verisi: str_cmp17470.txt
 * Amaç: str_cmp17470 fonksiyonunu hook ederek detektisyonu bypass etmek
 * Hedef: iOS PUBG 4.2
 * Framework: MobileSubstrate (No external dependencies)
 * 
 * Hooked Fonksiyonlar:
 *  - strcmp, sscanf, strncmp, strncpy, str_cmp17470
 * 
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <unistd.h>
#include <dispatch/dispatch.h>

// ============================================================================
// LOGGING MACROS
// ============================================================================

#define HOOK_LOG(fmt, ...) fprintf(stderr, "[BYPASS_HOOK] " fmt "\n", ##__VA_ARGS__); fflush(stderr)
#define ERROR_LOG(fmt, ...) fprintf(stderr, "[BYPASS_ERROR] " fmt "\n", ##__VA_ARGS__); fflush(stderr)
#define DEBUG_LOG(fmt, ...) fprintf(stderr, "[BYPASS_DEBUG] " fmt "\n", ##__VA_ARGS__); fflush(stderr)

// ============================================================================
// FUNCTION POINTERS
// ============================================================================

typedef int (*strcmp_t)(const char *s1, const char *s2);
typedef int (*strncmp_t)(const char *s1, const char *s2, size_t n);
typedef char* (*strncpy_t)(char *dest, const char *src, size_t n);
typedef int (*sscanf_t)(const char *str, const char *format, ...);
typedef int (*str_cmp17470_t)(const char *a1, const char *a2);

// Original functions
static strcmp_t g_strcmp_original = NULL;
static strncmp_t g_strncmp_original = NULL;
static strncpy_t g_strncpy_original = NULL;
static sscanf_t g_sscanf_original = NULL;
static str_cmp17470_t g_str_cmp17470_original = NULL;

// Statistics
static struct {
    int strcmp_calls;
    int strncmp_calls;
    int strncpy_calls;
    int sscanf_calls;
    int str_cmp17470_calls;
    int str_cmp17470_matches;
} g_stats = {0};

static dispatch_queue_t g_queue = NULL;

// ============================================================================
// CRITICAL FILES LIST
// ============================================================================

static const char *g_critical_files[] = {
    "comm.dat",
    "comm.zip",
    "sig4",
    "sig5",
    "tcjcfg.dat",
    "config2.dat",
    NULL
};

static int is_critical_file(const char *str) {
    if (!str) return 0;
    for (int i = 0; g_critical_files[i]; i++) {
        if (strstr(str, g_critical_files[i])) {
            return 1;
        }
    }
    return 0;
}

// ============================================================================
// HOOK IMPLEMENTATIONS
// ============================================================================

static int strcmp_hook(const char *s1, const char *s2) {
    dispatch_sync(g_queue, ^{
        g_stats.strcmp_calls++;
    });
    
    if (!s1 || !s2) return g_strcmp_original(s1, s2);
    
    if (is_critical_file(s1) || is_critical_file(s2)) {
        DEBUG_LOG("strcmp: '%s' vs '%s'", s1, s2);
    }
    
    return g_strcmp_original(s1, s2);
}

static int strncmp_hook(const char *s1, const char *s2, size_t n) {
    dispatch_sync(g_queue, ^{
        g_stats.strncmp_calls++;
    });
    
    if (!s1 || !s2) return g_strncmp_original(s1, s2, n);
    
    if (is_critical_file(s1) || is_critical_file(s2)) {
        DEBUG_LOG("strncmp: '%.20s' vs '%.20s'", s1, s2);
    }
    
    return g_strncmp_original(s1, s2, n);
}

static char* strncpy_hook(char *dest, const char *src, size_t n) {
    dispatch_sync(g_queue, ^{
        g_stats.strncpy_calls++;
    });
    
    if (!dest || !src) return g_strncpy_original(dest, src, n);
    
    if (is_critical_file(src)) {
        DEBUG_LOG("strncpy: '%s' (%zu bytes)", src, n);
    }
    
    return g_strncpy_original(dest, src, n);
}

static int sscanf_hook(const char *str, const char *format, ...) {
    dispatch_sync(g_queue, ^{
        g_stats.sscanf_calls++;
    });
    
    if (!str || !format) return g_sscanf_original(str, format);
    
    if (strstr(format, "%08x")) {
        DEBUG_LOG("sscanf: hex parsing detected");
    }
    
    return g_sscanf_original(str, format);
}

static int str_cmp17470_hook(const char *a1, const char *a2) {
    if (!a1 || !a2) {
        dispatch_sync(g_queue, ^{
            g_stats.str_cmp17470_calls++;
        });
        return g_str_cmp17470_original(a1, a2);
    }
    
    dispatch_sync(g_queue, ^{
        g_stats.str_cmp17470_calls++;
    });
    
    int is_critical = (is_critical_file(a1) || is_critical_file(a2));
    
    if (is_critical) {
        HOOK_LOG("str_cmp17470 CRITICAL: a1='%s', a2='%s'", a1, a2);
    }
    
    int result = g_str_cmp17470_original(a1, a2);
    
    if (result == 0) {
        dispatch_sync(g_queue, ^{
            g_stats.str_cmp17470_matches++;
        });
    }
    
    DEBUG_LOG("str_cmp17470 result: %d", result);
    
    return result;
}

// ============================================================================
// HOOK INSTALLATION
// ============================================================================

__attribute__((constructor))
static void bypass_init(void) {
    HOOK_LOG("===== Initializing Bypass Framework =====");
    
    if (!g_queue) {
        g_queue = dispatch_queue_create("com.bypass", NULL);
    }
    
    // Get original functions
    g_strcmp_original = (strcmp_t)dlsym(RTLD_DEFAULT, "strcmp");
    g_strncmp_original = (strncmp_t)dlsym(RTLD_DEFAULT, "strncmp");
    g_strncpy_original = (strncpy_t)dlsym(RTLD_DEFAULT, "strncpy");
    g_sscanf_original = (sscanf_t)dlsym(RTLD_DEFAULT, "sscanf");
    
    HOOK_LOG("strcmp: %p", (void*)g_strcmp_original);
    HOOK_LOG("strncmp: %p", (void*)g_strncmp_original);
    HOOK_LOG("strncpy: %p", (void*)g_strncpy_original);
    HOOK_LOG("sscanf: %p", (void*)g_sscanf_original);
    
    // Try to hook str_cmp17470 if we can find PUBG
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        
        // Find PUBG binary
        Dl_info info;
        for (uint64_t addr = 0x100000000; addr < 0x108000000; addr += 0x4000) {
            if (dladdr((void*)addr, &info) && info.dli_fname) {
                if (strstr(info.dli_fname, "PUBG") || strstr(info.dli_fname, "pubg")) {
                    uint64_t base = (uint64_t)info.dli_fbase;
                    g_str_cmp17470_original = (str_cmp17470_t)(base + 0x17470);
                    HOOK_LOG("Found PUBG at 0x%llx", base);
                    HOOK_LOG("str_cmp17470 at 0x%llx", (uint64_t)g_str_cmp17470_original);
                    break;
                }
            }
        }
    });
    
    HOOK_LOG("===== Framework Ready =====");
}

__attribute__((destructor))
static void bypass_cleanup(void) {
    HOOK_LOG("===== Statistics =====");
    dispatch_sync(g_queue, ^{
        HOOK_LOG("strcmp calls: %d", g_stats.strcmp_calls);
        HOOK_LOG("strncmp calls: %d", g_stats.strncmp_calls);
        HOOK_LOG("strncpy calls: %d", g_stats.strncpy_calls);
        HOOK_LOG("sscanf calls: %d", g_stats.sscanf_calls);
        HOOK_LOG("str_cmp17470 calls: %d", g_stats.str_cmp17470_calls);
        HOOK_LOG("str_cmp17470 matches: %d", g_stats.str_cmp17470_matches);
    });
    HOOK_LOG("===== Cleanup Done =====");
}

// ============================================================================
// EXPORTED API
// ============================================================================

void bypass_get_stats(int *strcmp_count, int *str_cmp17470_count) {
    dispatch_sync(g_queue, ^{
        if (strcmp_count) *strcmp_count = g_stats.strcmp_calls;
        if (str_cmp17470_count) *str_cmp17470_count = g_stats.str_cmp17470_calls;
    });
}

void bypass_dump_info(void) {
    HOOK_LOG("Dumping info...");
    dispatch_sync(g_queue, ^{
        HOOK_LOG("Total str_cmp17470 calls: %d", g_stats.str_cmp17470_calls);
    });
}

// ============================================================================
// END OF FILE
// ============================================================================
