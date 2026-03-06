ARCHS = arm64
DEBUG = 0
FINALPACKAGE = 1
FOR_RELEASE = 1

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ESP

# Dosya yolları
ESP_FILES = ESP/bypass.cpp $(wildcard ESP/*.mm) $(wildcard ESP/*.cpp) $(wildcard SDK/*.cpp) $(wildcard ESP/imgui/*.mm) $(wildcard ESP/imgui/*.cpp)

# Hataları susturan kritik bayraklar (Burayı aynen kopyala)
ESP_CCFLAGS = -w -std=gnu++14 -fno-rtti -fno-exceptions -DNDEBUG -Wno-module-import-in-extern-c -Wno-int-to-pointer-cast -Wno-return-stack-address -Wno-unused-private-field -Wno-macro-redefined
ESP_CFLAGS = -w -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-value -Wno-int-to-pointer-cast -Wno-macro-redefined

# Kütüphaneler (Substrate silindi, Dobby eklendi)
ESP_LIBRARIES = dobby
ESP_FRAMEWORKS = UIKit Foundation Security QuartzCore CoreGraphics AVFoundation

include $(THEOS_MAKE_PATH)/tweak.mk
