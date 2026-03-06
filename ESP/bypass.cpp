#include <string.h>
#include <stdint.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <unistd.h>
#include "dobby.h" // Dobby başlık dosyasının yolu doğru olmalı

// Orijinal fonksiyonlar
uintptr_t (*orig_str_cmp17470)(const char *a1, const char *a2);
int (*orig_strcmp)(const char *s1, const char *s2);

// Filtreleme
bool is_sus(const char *str) {
    if (!str) return false;
    if (strstr(str, "dobby") || strstr(str, "Shadow") || strstr(str, "__HOOK__TEXT")) {
        return true;
    }
    return false;
}

// Hook Fonksiyonları
uintptr_t fake_str_cmp17470(const char *a1, const char *a2) {
    if (is_sus(a1) || is_sus(a2)) {
        return 4294967279; 
    }
    return orig_str_cmp17470(a1, a2);
}

int fake_strcmp(const char *s1, const char *s2) {
    if (is_sus(s1) || is_sus(s2)) {
        return 1; 
    }
    return orig_strcmp(s1, s2);
}

void install_dobby_hooks() {
    uintptr_t base = (uintptr_t)_dyld_get_image_header(0);
    
    if (base != 0) {
        // Dobby ile Hook Atma (Substrate yerine)
        DobbyHook((void *)(base + 0x17470), (void *)fake_str_cmp17470, (void **)&orig_str_cmp17470);
        DobbyHook((void *)strcmp, (void *)fake_strcmp, (void **)&orig_strcmp);
    }
}

__attribute__((constructor))
static void load() {
    // Jailbreak olmayan cihazlarda constructor anında hook atmak daha sağlıklıdır
    install_dobby_hooks();
}
