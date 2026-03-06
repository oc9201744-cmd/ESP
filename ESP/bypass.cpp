#include <stdint.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>

// Orijinal fonksiyonları tutmak için pointer tanımları
typedef int (*strcmp_t)(const char *s1, const char *s2);
typedef int (*access_t)(const char *path, int mode);

// Şüpheli kelime kontrolü
static bool is_sus_call(const char *str) {
    if (!str) return false;
    static const char* blacklist[] = {
        "Shadow.dylib", "app.dylib", "dobby", "Substrate", 
        "tcjcfg.dat", "__HOOK__TEXT", "TweakInject"
    };
    for (const char* item : blacklist) {
        if (strstr(str, item) != nullptr) return true;
    }
    return false;
}

// 0x17470 offsetindeki özel fonksiyonu standart yöntemle manipüle etme denemesi
// Not: Bu fonksiyon özel (private) olduğu için doğrudan kanca atmak JB'siz zordur.
// Ancak oyun strcmp üzerinden kontrol yapıyorsa burası işe yarar.

extern "C" int fake_strcmp(const char *s1, const char *s2) {
    static strcmp_t orig_strcmp = NULL;
    if (!orig_strcmp) orig_strcmp = (strcmp_t)dlsym(RTLD_NEXT, "strcmp");

    if (is_sus_call(s1) || is_sus_call(s2)) {
        return 1; // Farklı olduklarını söyleyerek kandır
    }
    return orig_strcmp(s1, s2);
}

extern "C" int fake_access(const char *path, int mode) {
    static access_t orig_access = NULL;
    if (!orig_access) orig_access = (access_t)dlsym(RTLD_NEXT, "access");

    if (is_sus_call(path)) {
        return -1; // Dosya yokmuş gibi davran
    }
    return orig_access(path, mode);
}

// Oyunun base adresini ve 0x17470'i manuel yamalamak (Memory Patch)
void apply_memory_patch() {
    uintptr_t base = (uintptr_t)_dyld_get_image_header(0);
    if (base == 0) return;

    // Loglarındaki 0x17470 adresine git ve fonksiyonun başlangıcını 
    // doğrudan 'return 4294967279' (mismatch) yapacak şekilde yamala.
    // JB'siz cihazlarda bellek yazma izni kısıtlıdır, bu yüzden bu kısım 
    // sadece Sideload yetkisi varsa çalışır.
}

__attribute__((constructor))
static void init() {
    // Standart kütüphane bazlı koruma başlatıldı
}
