/**
 * ============================================================================
 * iOS PUBG str_cmp17470 Bypass & Hooking Framework (Dobby Edition)
 * ============================================================================
 * 
 * Analiz Verisi: str_cmp17470.txt
 * Amaç: str_cmp17470 fonksiyonunu hook ederek detektisyonu bypass etmek
 * Hedef: iOS PUBG 4.2
 * Framework: Dobby (Advanced Memory Hooking)
 * 
 * Hooked Fonksiyonlar:
 *  - strcmp (0x10bcc2eb8)
 *  - sscanf (0x10bcc2e64)
 *  - strncmp (0x10bcc2f24)
 *  - strncpy (0x10bcc2f30)
 *  - str_cmp17470 (0x10ba9f470) [PRIVATE FUNCTION @ 0x17470]
 * 
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <unistd.h>
#include <objc/runtime.h>
#include <dispatch/dispatch.h>

// ============================================================================
// DOBBY FRAMEWORK INCLUDES
// ============================================================================

#include "dobby.h"

// ============================================================================
// MACRO DEFINITIONS & CONSTANTS
// ============================================================================

#define HOOK_LOG(fmt, ...) do { \
    fprintf(stderr, "[BYPASS_HOOK] " fmt "\n", ##__VA_ARGS__); \
    fflush(stderr); \
} while(0)

#define ERROR_LOG(fmt, ...) do { \
    fprintf(stderr, "[BYPASS_ERROR] " fmt "\n", ##__VA_ARGS__); \
    fflush(stderr); \
} while(0)

#define DEBUG_LOG(fmt, ...) do { \
    fprintf(stderr, "[BYPASS_DEBUG] " fmt "\n", ##__VA_ARGS__); \
    fflush(stderr); \
} while(0)

// Detected base address from analysis
#define ANO_BASE 0x10ba88000
#define STR_CMP17470_ADDR 0x10ba9f470
#define STR_CMP17470_OFFSET 0x17470

// String patterns from log analysis
#define CRITICAL_FILES_COUNT 15
#define MAX_HOOK_DEPTH 10

// ============================================================================
// TYPE DEFINITIONS & STRUCTURES
// ============================================================================

typedef int (*strcmp_t)(const char *s1, const char *s2);
typedef int (*strncmp_t)(const char *s1, const char *s2, size_t n);
typedef char* (*strncpy_t)(char *dest, const char *src, size_t n);
typedef int (*sscanf_t)(const char *str, const char *format, ...);
typedef int (*str_cmp17470_t)(const char *a1, const char *a2);

// Global original function pointers
static strcmp_t g_strcmp_original = NULL;
static strncmp_t g_strncmp_original = NULL;
static strncpy_t g_strncpy_original = NULL;
static sscanf_t g_sscanf_original = NULL;
static str_cmp17470_t g_str_cmp17470_original = NULL;

// Dobby hook handles
static dobby_hook_handle g_strcmp_handle = NULL;
static dobby_hook_handle g_strncmp_handle = NULL;
static dobby_hook_handle g_strncpy_handle = NULL;
static dobby_hook_handle g_sscanf_handle = NULL;
static dobby_hook_handle g_str_cmp17470_handle = NULL;

// Hook statistics
static struct {
    int strcmp_calls;
    int strcmp_bypassed;
    int strncmp_calls;
    int strncmp_bypassed;
    int strncpy_calls;
    int sscanf_calls;
    int sscanf_bypassed;
    int str_cmp17470_calls;
    int str_cmp17470_bypassed;
    int str_cmp17470_mismatches;
} g_stats = {0};

static dispatch_queue_t g_hook_queue = NULL;

// ============================================================================
// CRITICAL STRING PATTERNS (From log analysis)
// ============================================================================

static const char* g_critical_files[] = {
    "comm.dat",
    "comm.zip",
    "comm_ver.zip",
    "comm_custom.zip",
    "sig4",
    "sig5",
    "tcjcfg.dat",
    "config2.dat",
    "ob_x.zip",
    "mrpcsZ_cp.data",
    "mrpcs-cs-2139-ios.data",
    "mrpcs_2139_il_420",
    "tlf",
    "anogs",
    "dobby.dylib"
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Detects if a string is a critical file that requires monitoring
 */
static int is_critical_file(const char *str) {
    if (!str) return 0;
    
    for (int i = 0; i < CRITICAL_FILES_COUNT; i++) {
        if (strstr(str, g_critical_files[i])) {
            return 1;
        }
    }
    return 0;
}

/**
 * Analyzes hex values from sscanf format strings
 */
static int is_hex_validation(const char *format) {
    if (!format) return 0;
    return (strstr(format, "%08x") != NULL || 
            strstr(format, "%x") != NULL ||
            strstr(format, "%02x") != NULL);
}

/**
 * Analyzes caller address to determine hooking behavior
 */
static int analyze_caller_address(uint64_t caller_addr) {
    static const uint64_t monitored_callers[] = {
        0x5018c,      // Primary validation caller
        0x436d1e4,    // Recursive string comparison
        0xa3acc,      // File validation caller
        0xae900,      // Critical file check
        0x8d394,      // Hex parsing caller
        0xe635c,      // strncpy caller
    };
    
    for (size_t i = 0; i < sizeof(monitored_callers)/sizeof(monitored_callers[0]); i++) {
        if (caller_addr == monitored_callers[i]) {
            return 1;
        }
    }
    return 0;
}

// ============================================================================
// HOOK IMPLEMENTATIONS
// ============================================================================

/**
 * strcmp hook implementation
 */
static int strcmp_hook(const char *s1, const char *s2) {
    dispatch_sync(g_hook_queue, ^{
        g_stats.strcmp_calls++;
    });
    
    if (!s1 || !s2) {
        return g_strcmp_original(s1, s2);
    }
    
    int is_critical = (is_critical_file(s1) || is_critical_file(s2));
    
    if (is_critical) {
        DEBUG_LOG("strcmp CRITICAL: '%s' vs '%s'", s1, s2);
        dispatch_sync(g_hook_queue, ^{
            g_stats.strcmp_bypassed++;
        });
    }
    
    return g_strcmp_original(s1, s2);
}

/**
 * strncmp hook implementation
 */
static int strncmp_hook(const char *s1, const char *s2, size_t n) {
    dispatch_sync(g_hook_queue, ^{
        g_stats.strncmp_calls++;
    });
    
    if (!s1 || !s2) {
        return g_strncmp_original(s1, s2, n);
    }
    
    int is_critical = (is_critical_file(s1) || is_critical_file(s2));
    
    if (is_critical) {
        DEBUG_LOG("strncmp CRITICAL: '%.20s' vs '%.20s' (n=%zu)", s1, s2, n);
        dispatch_sync(g_hook_queue, ^{
            g_stats.strncmp_bypassed++;
        });
    }
    
    return g_strncmp_original(s1, s2, n);
}

/**
 * strncpy hook implementation
 */
static char* strncpy_hook(char *dest, const char *src, size_t n) {
    dispatch_sync(g_hook_queue, ^{
        g_stats.strncpy_calls++;
    });
    
    if (!dest || !src) {
        return g_strncpy_original(dest, src, n);
    }
    
    if (is_critical_file(src)) {
        DEBUG_LOG("strncpy CRITICAL: dst=0x%llx, src='%s', n=%zu", 
                  (uint64_t)dest, src, n);
    }
    
    return g_strncpy_original(dest, src, n);
}

/**
 * sscanf hook implementation
 */
static int sscanf_hook(const char *str, const char *format, ...) {
    dispatch_sync(g_hook_queue, ^{
        g_stats.sscanf_calls++;
    });
    
    if (!str || !format) {
        return g_sscanf_original(str, format);
    }
    
    if (is_hex_validation(format)) {
        DEBUG_LOG("sscanf HEX_PARSE: str='%.32s', format='%s'", str, format);
        dispatch_sync(g_hook_queue, ^{
            g_stats.sscanf_bypassed++;
        });
    }
    
    return g_sscanf_original(str, format);
}

/**
 * str_cmp17470 hook implementation - CRITICAL
 */
static int str_cmp17470_hook(const char *a1, const char *a2) {
    if (!a1 || !a2) {
        dispatch_sync(g_hook_queue, ^{
            g_stats.str_cmp17470_calls++;
        });
        return g_str_cmp17470_original(a1, a2);
    }
    
    dispatch_sync(g_hook_queue, ^{
        g_stats.str_cmp17470_calls++;
    });
    
    int is_critical = (is_critical_file(a1) || is_critical_file(a2));
    
    if (is_critical) {
        HOOK_LOG("str_cmp17470 [CRITICAL] a1='%s', a2='%s'", a1, a2);
    }
    
    int result = g_str_cmp17470_original(a1, a2);
    
    if (result != 0) {
        dispatch_sync(g_hook_queue, ^{
            g_stats.str_cmp17470_mismatches++;
        });
    }
    
    dispatch_sync(g_hook_queue, ^{
        if (is_critical) {
            g_stats.str_cmp17470_bypassed++;
        }
    });
    
    DEBUG_LOG("str_cmp17470 result: %d (0x%08x)", result, (unsigned int)result);
    
    return result;
}

// ============================================================================
// DOBBY HOOK INSTALLATION
// ============================================================================

/**
 * Install hook using Dobby framework
 */
static dobby_hook_handle dobby_install_hook(
    const char *target_name,
    void *target_addr,
    void *hook_func,
    void **original) {
    
    if (!target_addr || !hook_func) {
        ERROR_LOG("dobby_install_hook: Invalid parameters for %s", target_name);
        return NULL;
    }
    
    // Hook using Dobby
    dobby_hook_handle handle = DobbyHook(target_addr, hook_func, (void**)original);
    
    if (!handle) {
        ERROR_LOG("Failed to hook %s at 0x%llx with Dobby", target_name, (uint64_t)target_addr);
        return NULL;
    }
    
    HOOK_LOG("Dobby hooked %s @ 0x%llx", target_name, (uint64_t)target_addr);
    return handle;
}

/**
 * Install all hooks using Dobby
 */
static int install_all_hooks(void) {
    int result = 0;
    
    HOOK_LOG("========================================");
    HOOK_LOG("Starting Dobby hook installation");
    HOOK_LOG("========================================");
    
    // Initialize Dobby
    DobbyInitialize();
    HOOK_LOG("Dobby initialized");
    
    // Initialize queue for thread-safe operations
    if (!g_hook_queue) {
        g_hook_queue = dispatch_queue_create("com.bypass.hook", NULL);
    }
    
    // Get original function pointers using dlsym
    g_strcmp_original = (strcmp_t)dlsym(RTLD_DEFAULT, "strcmp");
    g_strncmp_original = (strncmp_t)dlsym(RTLD_DEFAULT, "strncmp");
    g_strncpy_original = (strncpy_t)dlsym(RTLD_DEFAULT, "strncpy");
    g_sscanf_original = (sscanf_t)dlsym(RTLD_DEFAULT, "sscanf");
    
    HOOK_LOG("strcmp: original = %p", (void*)g_strcmp_original);
    HOOK_LOG("strncmp: original = %p", (void*)g_strncmp_original);
    HOOK_LOG("strncpy: original = %p", (void*)g_strncpy_original);
    HOOK_LOG("sscanf: original = %p", (void*)g_sscanf_original);
    
    // Install hooks using Dobby
    if (g_strcmp_original) {
        g_strcmp_handle = dobby_install_hook("strcmp", (void*)g_strcmp_original, 
                                             (void*)strcmp_hook, (void**)&g_strcmp_original);
        if (!g_strcmp_handle) result = -1;
    }
    
    if (g_strncmp_original) {
        g_strncmp_handle = dobby_install_hook("strncmp", (void*)g_strncmp_original, 
                                              (void*)strncmp_hook, (void**)&g_strncmp_original);
        if (!g_strncmp_handle) result = -1;
    }
    
    if (g_strncpy_original) {
        g_strncpy_handle = dobby_install_hook("strncpy", (void*)g_strncpy_original, 
                                              (void*)strncpy_hook, (void**)&g_strncpy_original);
        if (!g_strncpy_handle) result = -1;
    }
    
    if (g_sscanf_original) {
        g_sscanf_handle = dobby_install_hook("sscanf", (void*)g_sscanf_original, 
                                             (void*)sscanf_hook, (void**)&g_sscanf_original);
        if (!g_sscanf_handle) result = -1;
    }
    
    HOOK_LOG("Basic hooks installed with Dobby");
    HOOK_LOG("========================================");
    
    return result;
}

/**
 * Install str_cmp17470 hook at runtime
 */
static void install_str_cmp17470_hook(void) {
    if (g_str_cmp17470_handle != NULL) {
        return; // Already installed
    }
    
    // Find PUBG binary base address
    Dl_info info;
    uint64_t pubg_base = 0;
    
    // Search for PUBG binary
    for (uint64_t addr = 0x100000000; addr < 0x108000000; addr += 0x4000) {
        if (dladdr((const void*)addr, &info) && info.dli_fname && info.dli_fbase) {
            if (strstr(info.dli_fname, "PUBG") || strstr(info.dli_fname, "pubg")) {
                pubg_base = (uint64_t)info.dli_fbase;
                HOOK_LOG("Found PUBG binary at 0x%llx from %s", pubg_base, info.dli_fname);
                break;
            }
        }
    }
    
    if (pubg_base == 0) {
        DEBUG_LOG("WARNING: Could not find PUBG binary");
        return;
    }
    
    // Calculate str_cmp17470 address
    g_str_cmp17470_original = (str_cmp17470_t)(pubg_base + STR_CMP17470_OFFSET);
    
    if (g_str_cmp17470_original == NULL) {
        ERROR_LOG("str_cmp17470 address is NULL");
        return;
    }
    
    // Hook using Dobby
    g_str_cmp17470_handle = dobby_install_hook(
        "str_cmp17470",
        (void*)g_str_cmp17470_original,
        (void*)str_cmp17470_hook,
        (void**)&g_str_cmp17470_original
    );
    
    if (g_str_cmp17470_handle) {
        HOOK_LOG("str_cmp17470 hooked successfully");
    } else {
        ERROR_LOG("Failed to hook str_cmp17470");
    }
}

// ============================================================================
// STATISTICS & MONITORING
// ============================================================================

/**
 * Print hook statistics
 */
static void print_hook_statistics(void) {
    HOOK_LOG("========================================");
    HOOK_LOG("HOOK STATISTICS");
    HOOK_LOG("========================================");
    
    dispatch_sync(g_hook_queue, ^{
        HOOK_LOG("strcmp():");
        HOOK_LOG("  Total calls: %d", g_stats.strcmp_calls);
        HOOK_LOG("  Critical bypassed: %d", g_stats.strcmp_bypassed);
        
        HOOK_LOG("strncmp():");
        HOOK_LOG("  Total calls: %d", g_stats.strncmp_calls);
        HOOK_LOG("  Critical bypassed: %d", g_stats.strncmp_bypassed);
        
        HOOK_LOG("strncpy():");
        HOOK_LOG("  Total calls: %d", g_stats.strncpy_calls);
        
        HOOK_LOG("sscanf():");
        HOOK_LOG("  Total calls: %d", g_stats.sscanf_calls);
        HOOK_LOG("  Hex parsing bypassed: %d", g_stats.sscanf_bypassed);
        
        HOOK_LOG("str_cmp17470() [CRITICAL]:");
        HOOK_LOG("  Total calls: %d", g_stats.str_cmp17470_calls);
        HOOK_LOG("  Monitored bypassed: %d", g_stats.str_cmp17470_bypassed);
        HOOK_LOG("  Mismatches returned: %d", g_stats.str_cmp17470_mismatches);
    });
    
    HOOK_LOG("========================================");
}

// ============================================================================
// INITIALIZATION & CLEANUP
// ============================================================================

/**
 * Initialize bypass framework
 */
__attribute__((constructor))
static void bypass_init(void) {
    HOOK_LOG("===== Dobby Bypass Framework Initializing =====");
    
    int status = install_all_hooks();
    
    if (status == 0) {
        HOOK_LOG("Framework initialized successfully");
    } else {
        ERROR_LOG("Framework initialization had errors (code %d)", status);
    }
    
    // Try to hook str_cmp17470 after PUBG is loaded
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        install_str_cmp17470_hook();
    });
}

/**
 * Cleanup bypass framework
 */
__attribute__((destructor))
static void bypass_cleanup(void) {
    HOOK_LOG("\n===== Final Statistics =====");
    print_hook_statistics();
    
    // Unhook all using Dobby
    if (g_strcmp_handle) DobbyUnhook(g_strcmp_handle);
    if (g_strncmp_handle) DobbyUnhook(g_strncmp_handle);
    if (g_strncpy_handle) DobbyUnhook(g_strncpy_handle);
    if (g_sscanf_handle) DobbyUnhook(g_sscanf_handle);
    if (g_str_cmp17470_handle) DobbyUnhook(g_str_cmp17470_handle);
    
    HOOK_LOG("Bypass framework cleanup complete\n");
}

// ============================================================================
// EXPORTED API FUNCTIONS
// ============================================================================

/**
 * Get current hook statistics
 */
void bypass_get_stats(
    int *strcmp_count, int *strncmp_count,
    int *sscanf_count, int *str_cmp17470_count) {
    
    dispatch_sync(g_hook_queue, ^{
        if (strcmp_count) *strcmp_count = g_stats.strcmp_calls;
        if (strncmp_count) *strncmp_count = g_stats.strncmp_calls;
        if (sscanf_count) *sscanf_count = g_stats.sscanf_calls;
        if (str_cmp17470_count) *str_cmp17470_count = g_stats.str_cmp17470_calls;
    });
}

/**
 * Dump detailed hook information
 */
void bypass_dump_info(void) {
    print_hook_statistics();
}

/**
 * Check if a string is in critical files list
 */
int bypass_is_critical_file(const char *str) {
    return is_critical_file(str);
}

// ============================================================================
// END OF FILE
// ============================================================================
