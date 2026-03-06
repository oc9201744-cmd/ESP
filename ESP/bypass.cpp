#include <substrate.h>
#include <string.h>
#include <stdint.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <unistd.h>

// HATA BURADAYDI: GCD fonksiyonları için bu başlık şart
#include <dispatch/dispatch.h> 

// Orijinal fonksiyon saklayıcıları
int (*orig_strcmp)(const char *s1, const char *s2);
uintptr_t (*orig_str_cmp17470)(const char *a1, const char *a2);
int (*orig_access)(const char *path, int mode);

// Filtre listesi
bool is_cheat_file(const char *str) {
    if (!str) return false;
    static const char* blacklist[] = {
        "dobby", "Shadow.dylib", "app.dylib", "Substrate", 
        "AppSyncUnified", "tcjcfg.dat", "__HOOK__TEXT", 
        "Library/MobileSubstrate", "TweakInject"
    };
    for (const char* item : blacklist) {
        if (strcasestr(str, item) != nullptr) return true;
    }
    return false;
}

// 0x17470 Bypass
uintptr_t fake_str_cmp17470(const char *a1, const char *a2) {
    if (is_cheat_file(a1) || is_cheat_file(a2)) {
        return 4294967279; // Loglarındaki "farklı" sonucu
    }
    return orig_str_cmp17470(a1, a2);
}

// Access Bypass
int fake_access(const char *path, int mode) {
    if (is_cheat_file(path)) return -1;
    return orig_access(path, mode);
}

// Strcmp Bypass
int fake_strcmp(const char *s1, const char *s2) {
    if (is_cheat_file(s1) || is_cheat_file(s2)) return 1;
    return orig_strcmp(s1, s2);
}

void init_bypass_system() {
    uintptr_t base = (uintptr_t)_dyld_get_image_header(0);
    if (base > 0) {
        MSHookFunction((void *)(base + 0x17470), (void *)fake_str_cmp17470, (void **)&orig_str_cmp17470);
        MSHookFunction((void *)strcmp, (void *)fake_strcmp, (void **)&orig_strcmp);
        MSHookFunction((void *)access, (void *)fake_access, (void **)&orig_access);
    }
}

__attribute__((constructor))
static void load() {
    // dispatch_get_main_queue artık hata vermeyecek
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        init_bypass_system();
    });
}
