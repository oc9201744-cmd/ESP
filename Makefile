ARCHS = arm64
DEBUG = 0
FINALPACKAGE = 1
FOR_RELEASE = 1

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ESP

# bypass.cpp yolunu kontrol et
ESP_FILES = ESP/bypass.cpp $(wildcard ESP/*.mm) $(wildcard ESP/*.cpp) $(wildcard SDK/*.cpp) $(wildcard ESP/imgui/*.mm) $(wildcard ESP/imgui/*.cpp)

# JB olmadığı için substrate SİLİNDİ, Dobby dosyalarını buraya ekle (eğer lib olarak varsa)
# Eğer Dobby'yi kaynak kod olarak eklediysen ESP_FILES içinde olmalı.
ESP_LIBRARIES = dobby 

ESP_FRAMEWORKS = UIKit Foundation Security QuartzCore CoreGraphics AVFoundation

include $(THEOS_MAKE_PATH)/tweak.mk
