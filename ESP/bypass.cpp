#include <stdint.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <dispatch/dispatch.h>

// Dobby başlık dosyası (Dosya yolunun doğruluğundan emin olun)
#include "dobby.h"

// Orijinal fonksiyon saklayıcıları
static uintptr_t (*orig_str_cmp17470)(const char *a1, const char *a2);
static int (*orig_strcmp)(const char *s1, const char *s2);
static int (*orig_access)(const char *path, int mode);

/**
 * Filtreleme Mantığı:
 * Oyunun taradığı hile dosyalarını veya kütüphane izlerini yakalar.
 */
bool is_suspicious_call(const char *str) {
    if (!str) return false;
    
    static const char* blacklist[] = {
        "dobby", 
        "Shadow.dylib", 
        "app.dylib", 
        "Substrate", 
        "CydiaSubstrate", 
        "__HOOK__TEXT", 
        "tcjcfg.dat", 
        "Library/MobileSubstrate",
        "TweakInject"
    };

    for (const char* item : blacklist) {
        if (strcasestr(str, item) != nullptr) {
            return true;
        }
    }
    return false;
}

/**
 * str_cmp17470 Bypass (Offset: 0x17470)
 * Log Notu: "ret 0 mean ok they are same"
 * Eğer hile dosyası sorgulanıyorsa "farklı" (mismatch) kodu dönüyoruz.
 */
uintptr_t fake_str_cmp17470(const char *a1, const char *a2) {
    if (is_suspicious_call(a1) || is_suspicious_call(a2)) {
        // Loglardaki orijinal fark kodu (4294967279)
        return 4294967279; 
    }
    return orig_str_cmp17470(a1, a2);
}

/**
 * access Bypass
 * Dosyanın sistemde olup olmadığını kontrol ederken "yok" cevabı verir.
 */
int fake_access(const char *path, int mode) {
    if (is_suspicious_call(path)) {
        return -1; 
    }
    return orig_access(path, mode);
}

/**
 * strcmp Bypass
 */
int fake_strcmp(const char *s1, const char *s2) {
    if (is_suspicious_call(s1) || is_suspicious_call(s2)) {
        return 1; // 0 değilse "eşleşmedi" demektir
    }
    return orig_strcmp(s1, s2);
}

/**
 * Hook'ları yükleyen ana fonksiyon
 */
void apply_bypass_hooks() {
    uintptr_t base = (uintptr_t)_dyld_get_image_header(0);
    
    if (base != 0) {
        // Dobby ile Inline Hooking (Jailbreak gerektirmez)
        DobbyHook((void *)(base + 0x17470), (void *)fake_str_cmp17470, (void **)&orig_str_cmp17470);
        DobbyHook((void *)strcmp, (void *)fake_strcmp, (void **)&orig_strcmp);
        DobbyHook((void *)access, (void *)fake_access, (void **)&orig_access);
        
        // Konsola başarı mesajı (Opsiyonel)
        // printf("[BYPASS] Hooks applied successfully at base: %p\n", (void*)base);
    }
}

/**
 * Tweak yüklendiğinde otomatik çalışır
 */
__attribute__((constructor))
static void initialize_bypass() {
    // Oyunun ve Dobby'nin tamamen belleğe yerleşmesi için 1 saniye bekletiyoruz
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        apply_bypass_hooks();
    });
}
