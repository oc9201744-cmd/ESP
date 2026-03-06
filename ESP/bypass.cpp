#include <substrate.h>
#include <string.h>
#include <stdint.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <unistd.h>

// Orijinal fonksiyonlar
int (*orig_strcmp)(const char *s1, const char *s2);
uintptr_t (*orig_str_cmp17470)(const char *a1, const char *a2);
int (*orig_access)(const char *path, int mode);
int (*orig_stat)(const char *path, struct stat *buf);

// TESPİT EDİLMESİNİ İSTEMEDİĞİMİZ KELİMELER
bool is_sus_string(const char *str) {
    if (!str) return false;
    static const char* blacklist[] = {
        "Shadow.dylib", "app.dylib", "dobby", "Substrate", 
        "CydiaSubstrate", "tcjcfg.dat", "__HOOK__TEXT", "Library/MobileSubstrate"
    };
    for (const char* item : blacklist) {
        if (strstr(str, item) != nullptr) return true;
    }
    return false;
}

// 1. ÖZEL FONKSİYON BYPASS (0x17470)
// Log notu: "ret 0 mean ok they are same"
uintptr_t fake_str_cmp17470(const char *a1, const char *a2) {
    if (is_sus_string(a1) || is_sus_string(a2)) {
        // Eğer bizim hile dosyamız sorgulanıyorsa, "0" dönme (aynı değil de).
        // Loglardaki orijinal hata kodunu (farklılık kodunu) döndürüyoruz.
        return 4294967279; 
    }
    return orig_str_cmp17470(a1, a2);
}

// 2. DOSYA VARLIĞINI GİZLEME (access & stat)
// Oyun "Shadow.dylib var mı?" diye sorarsa "Hayır" (-1) cevabı verir.
int fake_access(const char *path, int mode) {
    if (is_sus_string(path)) {
        return -1; 
    }
    return orig_access(path, mode);
}

int fake_stat(const char *path, struct stat *buf) {
    if (is_sus_string(path)) {
        return -1;
    }
    return orig_stat(path, buf);
}

// 3. STANDART STRCMP BYPASS
int fake_strcmp(const char *s1, const char *s2) {
    if (is_sus_string(s1) || is_sus_string(s2)) {
        return 1; // 0 dönmezse "eşleşmedi" demektir.
    }
    return orig_strcmp(s1, s2);
}

void start_bypass() {
    uintptr_t base = (uintptr_t)_dyld_get_image_header(0);
    
    // Substrate Hooking
    if (base > 0) {
        // Loglardaki kritik fonksiyon
        MSHookFunction((void *)(base + 0x17470), (void *)fake_str_cmp17470, (void **)&orig_str_cmp17470);
        
        // Sistem çağrılarını gizle
        MSHookFunction((void *)strcmp, (void *)fake_strcmp, (void **)&orig_strcmp);
        MSHookFunction((void *)access, (void *)fake_access, (void **)&orig_access);
        MSHookFunction((void *)stat, (void *)fake_stat, (void **)&orig_stat);
    }
}

__attribute__((constructor))
static void initialize() {
    // Oyunun tam yüklenmesi için kısa bir bekleme gerekebilir
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        start_bypass();
    });
}
