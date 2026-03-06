#import "metalbiew.h"
#import "mahoa.h"
#include "sys/mman.h"
#include "Tools.h"
#import <AVFoundation/AVFoundation.h> 
#include <stdio.h>
#include <stdint.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#include "Icon.h"

#include "Iconcpp.h"

#include "ico_font.h"

#include <string>

#include <stdio.h>

#include <string.h>

#include "Vector3.hpp"

#include "Vector2.hpp"

#import <Foundation/Foundation.h>
#import "UE4.h"
#import "PubgLoad.h"
#include "imgui_notify.h"
#import "font.h"

#define kWidth[UIScreen mainScreen].bounds.size.width
#define kHeight[UIScreen mainScreen].bounds.size.height

NSString * bundle;
uint64_t GUObjectArray;
uint64_t GNameFun;
#define gName 0x104C0F1E8
#define gObject 0x10A288B80

@interface metalbiew() < MTKViewDelegate >
  @property(nonatomic, strong) IBOutlet MTKView * mtkView;
@property(nonatomic, strong) id < MTLDevice > device;
@property(nonatomic, strong) id < MTLCommandQueue > commandQueue;

@end

bool isAimKnocked = true;
bool IsValidAddress(kaddr addr) {
  return addr > 0x100000000 && addr < 0x2000000000;
}


bool anti1 = false;
bool anti2 = false;
bool anti3 = false;
bool anti4 = false;

bool giamgiat = false;

bool init1 = false;
bool init2 = false;
bool init3 = false;
bool init4 = false;
bool init5 = false;
bool WideView = false;
int WideValue = 120;

uintptr_t UE4;
kaddr module = (unsigned long) _dyld_get_image_vmaddr_slide(0);
namespace Options {
  int boxtype = 1;
  int healthbartype = 0;
  int Nationtype = 2;
  int DirectionLineSize = 70;
  int VehicleDirectionLineSize = 100;
  int offscreen_range = 40;
  int max_distance_offscreen = 400;
  int playersdistancessize = 600;
  bool esp_Outline = true;
  int distance_Radar = 150;
}

enum EAimTarget {
  Head = 0,
    Chest = 1
};

enum EAimTrigger {
  None = 0,
    Shooting = 1,
    Scoping = 2,
    Both = 3,
    Any = 4
};

long l1 = 0xFF544;
long l2 = 0xFFFFF;

int stack_20;
NSString * val_1;
NSString * val_x2;
int sort = 1, sort_1 = 3;
long RAMADDRESS = 0x4332443; 
bool stack_193 = NO;
using namespace std;
using namespace SDK;

static int Styleesp = 2;

bool ConfigSilentAimEnable = false;
struct sConfig {
  struct sESPMenu {
    bool Line;
    bool Box;
    bool Skeleton;
    bool Health;
    bool Name;
    bool Distance;
    bool TeamID;
    bool Weapon;
    bool Alert;
    bool Vehicle;
    bool IgnoreBot;
    bool LootBox;
    bool Throwables;
  };
  sESPMenu ESPMenu {
    false
  };

};
sConfig Config {
  false
};

struct JsonPreferences {
  enum EAimTarget {
    Head = 0,
      Chest = 1
  };

  enum EAimTrigger {
    None = 0,
      Shooting = 1,
      Scoping = 2,
      Both = 3,
      Any = 4
  };

  enum EAimPriority {
    DistancePriority = 0,
      FOVPriority = 1
  };

  struct sConfig {
    struct sAimMenu {
      bool EnableAllHack;
      bool Enable;
      bool Autofire;
      bool AimBot;
      bool CameraCache;
      EAimTarget Target;
      EAimTrigger Trigger;
      EAimPriority Priority;
      bool IgnoreKnocked;
      bool IgnoreBot;
      bool Prediction;
      bool VisCheck;
      bool LessRecoil;
      bool Norecoil;
      bool InstantHit;
      bool FastShoot;
      bool HeadShoot;
      bool ReCo;
      float Recc = 1.0f;
      bool HitX;
      int Cross = 200;
      bool test5;
      bool SpeedHack;
    };
    sAimMenu SilentAim {
      false
    };

  };
  sConfig Config {
    false
  };

}// SAQER
preferences;
UISlider * Auto1;
UISlider * Auto1Interval;
UISlider * sliderrr;
extern float TurnRate;
extern float NoScopeAimDisSliderVal;
extern float HiddenFOVSliderVal;
extern float NoScopeFOVSliderVal;
UISlider * aimspeed;
CGSize AutoFireCircelSize;
bool IsAirDrop = false;
int Interval = 1;
int counter;
int iAwareTexSiz = 20;
bool iAwareText = true;
int EspTextSiz = 9;
float EspBoxThik = 2.0f;
float EspSktonThik = 1.5f;
float IsfovSlider = 150.0f;
float AimSmooth = 5.0f;
bool AimTouch = false;
bool antibypass = false;
float g_disstance = 150.f;

int boxtype = 1;
int healthbartype = 0;
int Nationtype = 2;
int DirectionLineSize = 70;
int VehicleDirectionLineSize = 100;
int offscreen_range = 40;
int max_distance_offscreen = 400;
int playersdistancessize = 600;
bool esp_Outline = true;
int distance_Radar = 150;

uintptr_t ProcessEvent_Offset, AimBullet_Offset, AimBullet_Offset2, SetControlRotation_Offset;
#define SLEEP_TIME 1000 LL / 60 LL
#define TORAD(x)((x) * (M_PI / 180.f))
int g_screenWidth;
int g_screenHeight;
int screenWidth;
int screenHeight;
int screenDensity = 0;
int getEspFramerate;
int SCOLOR;
int scc;

char extra[30];
float density = -1;
float gDistance;
int localFiring {
  0
};
BOOL kaiguan1 = NO;
BOOL kaiguan2 = NO;
BOOL kaiguan3 = NO;
BOOL kaiguan4 = NO;
#define PI 3.14159265358979323846
#define __fastcall
bool ARWP = false;
bool SMGWP = false;
bool SNPWP = false;
bool otherWP = false;
bool AmmoWP = false;
bool LIGHTMW = false;
bool SHOTGUNWP = false;
bool scopewp = false;
bool POSTOLWP = false;
bool ARMORWP = false;
float IsAimBotRecc = 1.183f;
bool IsRecoilComparison = false;
static int Istargets = 2;

static int loaixe = 0;
static int xedacia = 0;
bool modxe = false;
bool tamnho = false;

bool effectm44 = false;

float dorong = 88.0f;

float IsDistance = 68;

float aimspeedsl() {
  float val1 = 20;
  return val1;
}
int aimpos() {
  float speedVal = 25;
  return speedVal;
}
int autodiss() {
  return Auto1.value;
}

NSString * resultx;
@implementation metalbiew
bool MenDeal;

-
(MTKView * ) mtkView {
  return (MTKView * ) self.view;
}
// SAQER
-
(void) loadView {
  self.view = [
    [MTKView alloc] initWithFrame: CGRectMake(0, 0, kWidth, kHeight)
  ];
}

-
(void) viewDidLoad {

  [super viewDidLoad];

  self.mtkView.device = self.device;
  self.mtkView.delegate = self;
  self.mtkView.clearColor = MTLClearColorMake(0, 0, 0, 0);
  self.mtkView.backgroundColor = [UIColor colorWithRed: 0 green: 0 blue: 0 alpha: 0];
  self.mtkView.clipsToBounds = YES;

}

-
(instancetype) initWithNibName: (nullable NSString * ) nibNameOrNil bundle: (nullable NSBundle * ) nibBundleOrNil {

  self = [super initWithNibName: nibNameOrNil bundle: nibBundleOrNil];

  _device = MTLCreateSystemDefaultDevice();
  _commandQueue = [_device newCommandQueue];
  if (!self.device) abort();

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO & io = ImGui::GetIO();
  (void) io;

  ImGui::CreateContext();
  ImGuiStyle * style = & ImGui::GetStyle();
  ImVec4 * colors = style -> Colors;

  style -> Alpha = 0.9f;

  style -> WindowBorderSize = 0.0f;
  style -> WindowTitleAlign = ImVec2(0.5, 0.5);
  style -> WindowPadding = ImVec2(15, 15);
  style -> WindowRounding = 15.0f;
  style -> FramePadding = ImVec2(5, 5);
  
  style -> FrameRounding = 10.0f;
  style -> ItemSpacing = ImVec2(12, 8);
  style -> ItemInnerSpacing = ImVec2(8, 6);
  style -> IndentSpacing = 25.0f;
  style -> ScrollbarSize = 15.0f;
  style -> ScrollbarRounding = 10.0f;
  style -> GrabMinSize = 20.0f;
  style -> GrabRounding = 10.0f;





colors[ImGuiCol_Text] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);      
colors[ImGuiCol_TextDisabled] = ImVec4(0.55f, 0.55f, 0.55f, 1.00f); 

colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.06f, 0.06f, 1.00f);
colors[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);

colors[ImGuiCol_Border] = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);

colors[ImGuiCol_FrameBg] = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
colors[ImGuiCol_FrameBgHovered] = ImVec4(0.18f, 0.18f, 0.18f, 1.00f);
colors[ImGuiCol_FrameBgActive] = ImVec4(0.22f, 0.22f, 0.22f, 1.00f);

colors[ImGuiCol_TitleBg] = ImVec4(0.07f, 0.07f, 0.07f, 1.00f);
colors[ImGuiCol_TitleBgActive] = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);

colors[ImGuiCol_MenuBarBg] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);


colors[ImGuiCol_Button] = ImVec4(1.00f, 0.90f, 0.20f, 0.95f);
colors[ImGuiCol_ButtonHovered] = ImVec4(1.00f, 0.94f, 0.35f, 1.00f);
colors[ImGuiCol_ButtonActive] = ImVec4(1.00f, 0.85f, 0.15f, 1.00f);


colors[ImGuiCol_Header] = ImVec4(1.00f, 0.90f, 0.20f, 0.85f);
colors[ImGuiCol_HeaderHovered] = ImVec4(1.00f, 0.94f, 0.35f, 0.95f);
colors[ImGuiCol_HeaderActive] = ImVec4(1.00f, 0.85f, 0.15f, 1.00f);


colors[ImGuiCol_SliderGrab] = ImVec4(1.00f, 0.90f, 0.20f, 1.00f);
colors[ImGuiCol_SliderGrabActive] = ImVec4(1.00f, 0.85f, 0.15f, 1.00f);


colors[ImGuiCol_CheckMark] = ImVec4(1.00f, 0.90f, 0.20f, 1.00f);




  
  for (int i = 0; i < ImGuiCol_COUNT; i++) {

  }
  ImFontConfig font_cfg;
  font_cfg.FontDataOwnedByAtlas = false;

  io.Fonts -> AddFontFromMemoryTTF((void * ) jijia_data, jijia_size, 15.0f, NULL,
    io.Fonts -> GetGlyphRangesChineseFull());

  ImGui::MergeIconsWithLatestFont(12.f, false);
  ImGui_ImplMetal_Init(_device);

  return self;
}

ImVec4 to_vec4(float r, float g, float b, float a) {
  return ImVec4(r / 255.0, g / 255.0, b / 255.0, a / 255.0);
}
static auto start = std::chrono::steady_clock::now();
static auto noww = std::chrono::high_resolution_clock::now();
auto elapsedd = std::chrono::duration_cast < std::chrono::milliseconds > (noww - start).count();
namespace Settings {
  static int Tab = 0;
}

- (void) drawInMTKView: (MTKView * ) view {

    ImGuiIO & io = ImGui::GetIO();
    io.DisplaySize.x = view.bounds.size.width;
    io.DisplaySize.y = view.bounds.size.height;

    #if TARGET_OS_OSX
    CGFloat framebufferScale = view.window.screen.backingScaleFactor ? : NSScreen.mainScreen.backingScaleFactor;
    #else
    CGFloat framebufferScale = view.window.screen.nativeScale;
    #endif
    io.DisplayFramebufferScale = ImVec2(framebufferScale, framebufferScale);
    io.DeltaTime = 1 / float(view.preferredFramesPerSecond ? : 60);

    id < MTLCommandBuffer > commandBuffer = [self.commandQueue commandBuffer];

    if (MenDeal == true) {
      [self.view setUserInteractionEnabled: YES];
    } else if (MenDeal == false) {
      [self.view setUserInteractionEnabled: NO];
    }

    MTLRenderPassDescriptor * renderPassDescriptor = view.currentRenderPassDescriptor;
    if (renderPassDescriptor != nil) {
      id < MTLRenderCommandEncoder > renderEncoder = [commandBuffer renderCommandEncoderWithDescriptor: renderPassDescriptor];
      [renderEncoder pushDebugGroup: @ ""];

      ImGui_ImplMetal_NewFrame(renderPassDescriptor);
      ImGui::NewFrame();

      CGFloat x = (([UIApplication sharedApplication].windows[0].rootViewController.view.frame.size.width) - 360) / 2;
      CGFloat y = (([UIApplication sharedApplication].windows[0].rootViewController.view.frame.size.height) - 360) / 2;
      static ImVec4 active = to_vec4(158, 158, 158, 255);
      static ImVec4 inactive = to_vec4(66, 66, 66, 255);

      ImGui::SetNextWindowPos(ImVec2(x,
        y), ImGuiCond_FirstUseEver);
      ImGui::SetNextWindowSize(ImVec2(500,
        320), ImGuiCond_FirstUseEver);

      if (MenDeal == true) {

        ImGui::Begin(("SAQER | Free Src Soon!")  , & MenDeal);

        {
          ImGui::Columns(2);
          ImGui::SetColumnOffset(1, 140);
          {

            if (ImGui::Button(ICON_FA_GEAR "ESP", ImVec2(100, 85)))
              Settings::Tab = 8;

            if (ImGui::Button(ICON_FA_CROSSHAIRS "AIM TRACK", ImVec2(100, 85)))
              Settings::Tab = 9;

          }
        }
        ImGui::NextColumn();

        
        if (Settings::Tab == 8) {

          ImGui::Spacing();
          
          if (ImGui::BeginTable("esp_toggles", 4, ImGuiTableFlags_SizingFixedFit)) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Checkbox((" LINE"), & Config.ESPMenu.Line);

            ImGui::TableSetColumnIndex(1);
            ImGui::Checkbox((" BOX"), & Config.ESPMenu.Box);

            ImGui::TableSetColumnIndex(2);
            ImGui::Checkbox((" HEALTH"), & Config.ESPMenu.Health);

            ImGui::TableSetColumnIndex(3);
            ImGui::Checkbox((" NAME"), & Config.ESPMenu.Name);

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Checkbox((" SKELETON"), & Config.ESPMenu.Skeleton);

            ImGui::TableSetColumnIndex(1);
            ImGui::Checkbox((" DISTANCE"), & Config.ESPMenu.Distance);

            ImGui::TableSetColumnIndex(2);
            ImGui::Checkbox((" WEAPON"), & Config.ESPMenu.Weapon);

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Checkbox((" 360 ALERT"), & Config.ESPMenu.Alert);

            ImGui::TableSetColumnIndex(1);
            ImGui::Checkbox((" IGNORE BOT"), & Config.ESPMenu.IgnoreBot);

            ImGui::EndTable();
          }

          ImGui::EndTabItem();

        } else if (Settings::Tab == 9) {

          ImGui::Spacing();
          if (ImGui::Checkbox(("BULLET TRACK SIFT"), &
              preferences.Config.SilentAim.Enable)) {}

          if (ImGui::Checkbox(("AIM BOT"), &
              preferences.Config.SilentAim.AimBot)) {}

          ImGui::Text(("FOV: "));
          ImGui::SameLine();

          ImGui::SliderInt("##foov", & preferences.Config.SilentAim.Cross, 1.0f, 370.0f);
          ImGui::Text(("Limit: "));
          ImGui::SameLine();

          ImGui::SliderFloat("##distance", & g_disstance, 1.0f, 300.f);
          ImGui::Text(("Target: "));
          ImGui::SameLine();
          static
          const char * targets[] = {
            ("Head"),
            ("Body")
          };
          if (ImGui::Combo(("##Target"),
              (int * ) & preferences.Config.SilentAim.Target,
              targets,
              2,
              -1)) {}

          ImGui::Text(("Trigger:"));
          ImGui::SameLine();
          static
        const char* triggers[] = {
            "Shooting",
            "Scope",
            "Aiming",
            "Scope & Aiming",
            "Any (Both)"
        };

          if (ImGui::Combo(("##Trigger"),
              (int * ) & preferences.Config.SilentAim.Trigger,
              triggers,
              5,
              -1)) {}

          ImGui::SameLine();
          if (ImGui::Checkbox("IgnoreKnocked", & preferences.Config.SilentAim.IgnoreKnocked)) {}
          ImGui::SameLine();
          if (ImGui::Checkbox("IgnoreBot", & preferences.Config.SilentAim.IgnoreBot)) {}

          ImGui::Checkbox("Wide View", & WideView);
          if (WideView) {
            ImGui::SliderInt("Field of View", & WideValue, 90, 140);

          }
          ImGui::EndTabItem();

        }
        ImGui::EndTabBar(); 
      }
      ImGui::End();

      ImGui::Render();
      ImDrawData * draw_data = ImGui::GetDrawData();
      ImGui_ImplMetal_RenderDrawData(draw_data,
        commandBuffer,
        renderEncoder);

      [renderEncoder popDebugGroup];
      [renderEncoder endEncoding];

      [commandBuffer presentDrawable: view.currentDrawable];

    }

    [commandBuffer commit];

  }

  -
  (void) mtkView: (MTKView * ) view drawableSizeWillChange: (CGSize) size {}

#pragma mark - Interaction

  -
  (void) updateIOWithTouchEvent: (UIEvent * ) event {
    UITouch * anyTouch = event.allTouches.anyObject;
    CGPoint touchLocation = [anyTouch locationInView: self.view];
    ImGuiIO & io = ImGui::GetIO();
    io.MousePos = ImVec2(touchLocation.x,
      touchLocation.y);

    BOOL hasActiveTouch = NO;
    for (UITouch * touch in event.allTouches) {
      if (touch.phase != UITouchPhaseEnded && touch.phase != UITouchPhaseCancelled) {
        hasActiveTouch = YES;
        break;
      }
    }
    io.MouseDown[0] = hasActiveTouch;
  }

  -
  (void) touchesBegan: (NSSet < UITouch * > * ) touches withEvent: (UIEvent * ) event {
    [self updateIOWithTouchEvent: event];
  }

  -
  (void) touchesMoved: (NSSet < UITouch * > * ) touches withEvent: (UIEvent * ) event {
    [self updateIOWithTouchEvent: event];
  }

  -
  (void) touchesCancelled: (NSSet < UITouch * > * ) touches withEvent: (UIEvent * ) event {
    [self updateIOWithTouchEvent: event];
  }

  -
  (void) touchesEnded: (NSSet < UITouch * > * ) touches withEvent: (UIEvent * ) event {
    [self updateIOWithTouchEvent: event];
  }

#pragma esp method-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --

typedef uintptr_t kaddr;
using namespace std;
using namespace SDK;

string encryptDecrypt(string toEncrypt) {
  char key[3] = {
    'K',
    'C',
    'Q'
  }; 
  string output = toEncrypt;
  for (int i = 0; i < toEncrypt.size(); i++)
    output[i] = toEncrypt[i] ^ key[i % (sizeof(key) / sizeof(char))];
  return output;
}


uint64_t getBaseAddress(const char * fileName) {
  for (int i = 0; i < _dyld_image_count(); i++) {
    if (strstr(_dyld_get_image_name(0), fileName)) {
      return _dyld_get_image_vmaddr_slide(0);
    }
  }
  return 0;
}

uint64_t getRealOffset(uint64_t offset) {
  uint64_t vmaddr = getBaseAddress("ShadowTrackerExtra");
  return vmaddr + offset;
}
long obbbbl() {

  return getRealOffset(gObject);
};
UWorld * GEWorld;
int GWorldNum = 0;
TUObjectArray gobjects;
UWorld * GetFullWorld() {
  if (GWorldNum == 0) {
    gobjects = UObject::GUObjectArray -> ObjObjects;
    for (int i = 0; i < gobjects.Num(); i++)
      if (auto obj = gobjects.GetByIndex(i)) {
        if (obj -> IsA(UEngine::StaticClass())) {
          auto GEngine = (UEngine * ) obj;
          if (GEngine) {
            tslFont = GEngine -> MediumFont;
            robotoTinyFont = GEngine -> MediumFont;
            robotoFont = GEngine -> MediumFont;
            auto ViewPort = GEngine -> GameViewport;
            if (ViewPort) {
              GEWorld = ViewPort -> World;
              GWorldNum = i;
              return ViewPort -> World;
            }
          }
        }
      }
  } else {
    auto GEngine = (UEngine * )(gobjects.GetByIndex(GWorldNum));
    if (GEngine) {
      tslFont = GEngine -> MediumFont;
      robotoTinyFont = GEngine -> MediumFont;
      robotoFont = GEngine -> MediumFont;
      auto ViewPort = GEngine -> GameViewport;
      if (ViewPort) {
        GEWorld = ViewPort -> World;
        return ViewPort -> World;
      }
    }
  }
  return 0;
}

TNameEntryArray * GetGNames() {

  return ((TNameEntryArray * ( * )())(
    (unsigned long) _dyld_get_image_vmaddr_slide(0) + gName))();
}

std::vector < AActor * > getActors() {
  auto World = GetFullWorld();
  if (!World)
    return std::vector < AActor * > ();

  auto PersistentLevel = World -> PersistentLevel;
  if (!PersistentLevel)
    return std::vector < AActor * > ();

  auto Actors = * (TArray < AActor * > * )((uintptr_t) PersistentLevel + 0xa0);

  std::vector < AActor * > actors;
  for (int i = 0; i < Actors.Num(); i++) {
    auto Actor = Actors[i];
    if (Actor) {
      actors.push_back(Actor);
    }
  }
  return actors;
}
template < class T > void GetAllActors(std::vector < T * > & Actors) {
  UGameplayStatics * gGameplayStatics = (UGameplayStatics * ) gGameplayStatics -> StaticClass();
  auto GWorld = GetFullWorld();
  if (GWorld) {
    TArray < AActor * > Actors2;
    gGameplayStatics -> GetAllActorsOfClass((UObject * ) GWorld,
      T::StaticClass(), &
      Actors2);
    for (int i = 0; i < Actors2.Num(); i++) {
      Actors.push_back((T * ) Actors2[i]);
    }
  }
}
FVector GetBoneLocationByName(ASTExtraPlayerCharacter * Actor,
  const char * BoneName) {
  return Actor -> GetBonePos(BoneName,
    FVector());
}

struct sRegion {
  kaddr start, end;
};

std::vector < sRegion > trapRegions;

bool isObjectInvalid(UObject * obj) {
  if (!Tools::IsPtrValid(obj)) {
    return true;
  }
  if (!Tools::IsPtrValid(obj -> ClassPrivate)) {
    return true;
  }
  if (obj -> InternalIndex <= 0) {
    return true;
  }
  if (obj -> NamePrivate.ComparisonIndex <= 0) {
    return true;
  }
  if ((kaddr)(obj) % sizeof(kaddr) != 0x0 && (kaddr)(obj) % sizeof(kaddr) != 0x4) {
    return true;
  }
  if (std::any_of(trapRegions.begin(), trapRegions.end(), [ & ](const sRegion & region) {
      return ((kaddr) obj) >= region.start && ((kaddr) obj) <= region.end;
    }) || std::any_of(trapRegions.begin(), trapRegions.end(), [ & ](const sRegion & region) {
      return ((kaddr) obj -> ClassPrivate) >= region.start && ((kaddr) obj -> ClassPrivate) <= region.end;
    })) {
    return true;
  }
  return false;
}// SAQER

bool WriteAddr(void * addr, void * buffer, size_t length) {
  unsigned long page_size = sysconf(_SC_PAGESIZE);
  unsigned long size = page_size * sizeof(kaddr);
  return mprotect((void * )((kaddr) addr - ((kaddr) addr % page_size) - page_size),
    (size_t) size,
    PROT_EXEC | PROT_READ | PROT_WRITE) == 0 && memcpy(addr,
    buffer,
    length) != 0;
}
template < typename T >
  void Write(kaddr addr, T value) {
    WriteAddr((void * ) addr, &
      value,
      sizeof(T));
  }

class Rect2 {
  public: float x;
  float y;
  float width;
  float height;

  Rect2() {
    this -> x = 0;
    this -> y = 0;
    this -> width = 0;
    this -> height = 0;
  }

  Rect2(float x,
    float y,
    float width,
    float height) {
    this -> x = x;
    this -> y = y;
    this -> width = width;
    this -> height = height;
  }

  bool operator == (const Rect2 & src) const {
    return (src.x == this -> x && src.y == this -> y && src.height == this -> height &&
      src.width == this -> width);
  }

  bool operator != (const Rect2 & src) const {
    return (src.x != this -> x && src.y != this -> y && src.height != this -> height &&
      src.width != this -> width);
  }
};
struct FLinearColor visCol;
ASTExtraPlayerCharacter * g_LocalPlayer;
ASTExtraPlayerController * g_PlayerController;
#define COLOR_BLACK FLinearColor(0, 0, 0, 1.f)
#define COLOR_WHITE FLinearColor(1.f, 1.f, 1.f, 1.f)
#define COLOR_RED FLinearColor(1.f, 0, 0, 1.f)
#define COLOR_LIME FLinearColor(0, 1.f, 0, 1.f)
#define COLOR_BLUE FLinearColor(0, 0, 1.f, 1.f)
#define COLOR_CAR FLinearColor(1.f, 0.5f, 1.f, 1.f)
#define GREEN FLinearColor(0 / 255.f, 153 / 255.f, 0 / 255.f, 1.f)
#define ABU FLinearColor(0 / 255.f, 204 / 255.f, 204 / 255.f, 1.f)
#define COLOR_GREEN FLinearColor(0, 0.5f, 0, 1.f)
#define COLOR_PLAYER FLinearColor(1.000f, 0.620f, 0.150f, 1.000f)
#define COLOR_YELLOW FLinearColor(1.000f, 1.000f, 0.000f, 1.000f)

void DrawRectangle(AHUD * HUD, FVector2D Pos, float Width, float Height, float Thickness, FLinearColor Color) {
  HUD -> DrawLine(Pos.X, Pos.Y, Pos.X + Width, Pos.Y, Color, Thickness);
  HUD -> DrawLine(Pos.X, Pos.Y, Pos.X, Pos.Y + Height, Color, Thickness);
  HUD -> DrawLine(Pos.X + Width, Pos.Y, Pos.X + Width, Pos.Y + Height, Color, Thickness);
  HUD -> DrawLine(Pos.X, Pos.Y + Height, Pos.X + Width, Pos.Y + Height, Color, Thickness);
}

FVector2D WorldToRadar(float Yaw, FVector Origin, FVector LocalOrigin, float PosX, float PosY,
  FVector Size, bool & outbuff) {
  bool flag = false;
  double num = (double) Yaw;
  double num2 = num * 0.017453292519943295;
  float num3 = (float) std::cos(num2);
  float num4 = (float) std::sin(num2);
  float num5 = Origin.X - LocalOrigin.X;
  float num6 = Origin.Y - LocalOrigin.Y;
  FVector2D vector;
  vector.X = (num6 * num3 - num5 * num4) / 150.f;
  vector.Y = (num5 * num3 + num6 * num4) / 150.f;
  FVector2D vector2;
  vector2.X = vector.X + PosX + Size.X / 2.f;
  vector2.Y = -vector.Y + PosY + Size.Y / 2.f;
  bool flag2 = vector2.X > PosX + Size.X;
  if (flag2) {
    vector2.X = PosX + Size.X;
  } else {
    bool flag3 = vector2.X < PosX;
    if (flag3) {
      vector2.X = PosX;
    }
  }
  bool flag4 = vector2.Y > PosY + Size.Y;
  if (flag4) {
    vector2.Y = PosY + Size.Y;
  } else {
    bool flag5 = vector2.Y < PosY;
    if (flag5) {
      vector2.Y = PosY;
    }
  }
  bool flag6 = vector2.Y == PosY || vector2.X == PosX;
  if (flag6) {
    flag = true;
  }
  outbuff = flag;
  return vector2;
}

void VectorAnglesRadar(Vector3 & forward, FVector & angles) {
  if (forward.X == 0.f && forward.Y == 0.f) {
    angles.X = forward.Z > 0.f ? -90.f : 90.f;
    angles.Y = 0.f;
  } else {
    angles.X = RAD2DEG(atan2(-forward.Z, forward.Magnitude(forward)));
    angles.Y = RAD2DEG(atan2(forward.Y, forward.X));
  }
  angles.Z = 0.f;
}
FRotator ToRotator(FVector local, FVector target) {
  FVector rotation;
  rotation.X = local.X - target.X;
  rotation.Y = local.Y - target.Y;
  rotation.Z = local.Z - target.Z;

  FRotator newViewAngle = {
    0
  };

  float hyp = sqrt(rotation.X * rotation.X + rotation.Y * rotation.Y);

  newViewAngle.Pitch = -atan(rotation.Z / hyp) * (180.f / (float) 3.14159265358979323846);
  newViewAngle.Yaw = atan(rotation.Y / rotation.X) * (180.f / (float) 3.14159265358979323846);
  newViewAngle.Roll = (float) 0.f;

  if (rotation.X >= 0.f)
    newViewAngle.Yaw += 180.0f;

  return newViewAngle;
}


void DrawArrows(AHUD * hud, std::array < FVector2D, 39 > Loc, float thickness, FLinearColor color) {
  for (int i = 10; i < 25; i++) {
    DrawLine(hud, Loc.at(i), Loc.at(7), thickness, color);
  }
  for (int i = 26; i < 38; i++) {
    DrawLine(hud, Loc.at(i), Loc.at(7), thickness + 1.5, color);
    DrawLine(hud, Loc.at(i), Loc.at(8), thickness + 1.5f, color);
    DrawLine(hud, Loc.at(i), Loc.at(9), thickness + 1.5f, color);
  }
  DrawLine(hud, Loc.at(0), Loc.at(1), thickness * 1.f, COLOR_BLACK);
  DrawLine(hud, Loc.at(1), Loc.at(2), thickness * 1.f, COLOR_BLACK);
  DrawLine(hud, Loc.at(2), Loc.at(6), thickness * 1.f, COLOR_BLACK);
  DrawLine(hud, Loc.at(6), Loc.at(5), thickness * 1.f, COLOR_BLACK);
  DrawLine(hud, Loc.at(5), Loc.at(4), thickness * 1.f, COLOR_BLACK);
  DrawLine(hud, Loc.at(4), Loc.at(3), thickness * 1.f, COLOR_BLACK);
  DrawLine(hud, Loc.at(3), Loc.at(0), thickness * 1.f, COLOR_BLACK);
}

void DrawFilledRectangle(AHUD * HUD, FVector2D Pos, float Width, float Height, FLinearColor Color) {
  HUD -> DrawRect(Color, Pos.X, Pos.Y, Width, Height);
}

void DrawLine(AHUD * HUD, FVector2D posFrom, FVector2D posTo, float Thickness, FLinearColor Color) {
  HUD -> DrawLine(posFrom.X, posFrom.Y, posTo.X, posTo.Y, Color, Thickness);
}
void Box4Line(AHUD * HUD, float thicc, int x, int y, int w, int h, FLinearColor color) {
  int iw = w / 4;
  int ih = h / 4;

  
  

  
  HUD -> DrawLine(x, y, x + iw, y, color, thicc);
  HUD -> DrawLine(x + w - iw, y, x + w, y, color, thicc);
  HUD -> DrawLine(x, y, x, y + ih, color, thicc);
  HUD -> DrawLine(x + w - 1, y, x + w - 1, y + ih, color, thicc);

  
  HUD -> DrawLine(x, y + h, x + iw, y + h, color, thicc);
  HUD -> DrawLine(x + w - iw, y + h, x + w, y + h, color, thicc);
  HUD -> DrawLine(x, y + h - ih, x, y + h, color, thicc);
  HUD -> DrawLine(x + w - 1, y + h - ih, x + w - 1, y + h, color, thicc);
}
#define TSL_FONT_DEFAULT_SIZE 20
static UFont * robotoFont = 0, * robotoTinyFont = 0, * tslFont = 0;

void DrawOutlinedText(AHUD * HUD, FString Text, FVector2D Pos, FLinearColor Color, FLinearColor OutlineColor, bool isCenter = false) {
  UCanvas * Canvas = HUD -> Canvas;
  Canvas -> K2_DrawText(robotoFont, Text, Pos, Color, 1.f, {}, {}, isCenter, isCenter, true, OutlineColor);
}

void DrawText(AHUD * HUD, FString Text, FVector2D Pos, FLinearColor Color, bool isCenter = false) {
  UCanvas * Canvas = HUD -> Canvas;
  Canvas -> K2_DrawText(robotoFont, Text, Pos, Color, 1.f, {}, {}, isCenter, isCenter, false, {});
}

void DrawSmallOutlinedText(AHUD * HUD, FString Text, FVector2D Pos, FLinearColor Color, FLinearColor OutlineColor, bool isCenter = false) {
  UCanvas * Canvas = HUD -> Canvas;
  Canvas -> K2_DrawText(robotoTinyFont, Text, Pos, Color, 1.f, {}, {}, isCenter, isCenter, true, OutlineColor);
}

void DrawSmallText(AHUD * HUD, FString Text, FVector2D Pos, FLinearColor Color, bool isCenter = false) {
  UCanvas * Canvas = HUD -> Canvas;
  Canvas -> K2_DrawText(robotoTinyFont, Text, Pos, Color, 1.f, {}, {}, isCenter, isCenter, false, {});
}
void DrawTextcan(AHUD * HUD, FString Text, FVector2D Pos, FLinearColor Color, FLinearColor OutlineColor, bool isCenter = true) {
  UCanvas * Canvas = HUD -> Canvas;
  Canvas -> K2_DrawText(tslFont, Text, Pos, Color, 1.f, {}, {}, isCenter, isCenter, true, OutlineColor);
}
void DrawCircle(AHUD * HUD, int x, int y, int radius, int numsides, FLinearColor OutlineColor) {
  float Step = M_PI * 2.0 / numsides;
  int Count = 0;
  FVector2D V[128];
  for (float a = 0; a < M_PI * 2.0; a += Step) {
    float X1 = radius * cos(a) + x;
    float Y1 = radius * sin(a) + y;
    float X2 = radius * cos(a + Step) + x;
    float Y2 = radius * sin(a + Step) + y;
    V[Count].X = X1;
    V[Count].Y = Y1;
    V[Count + 1].X = X2;
    V[Count + 1].Y = Y2;
    HUD -> Canvas -> K2_DrawLine(FVector2D({
      V[Count].X,
      V[Count].Y
    }), FVector2D({
      X2,
      Y2
    }), 1.f, OutlineColor);
  }
}
void DrawFilledCircle(AHUD * HUD, int x, int y, int radius, int numsides, FLinearColor OutlineColor, FLinearColor FillColor) {
  float Step = M_PI * 2.0 / numsides;
  FVector2D Center(x, y);
  FVector2D V[128];
  for (int i = 0; i < numsides; ++i) {
    
    float Angle = Step * i;
    V[i].X = Center.X + radius * cos(Angle);
    V[i].Y = Center.Y + radius * sin(Angle);

    
    HUD -> Canvas -> K2_DrawLine(Center, V[i], 1.f, FillColor);
  }

  
  for (int i = 0; i < numsides; ++i) {
    HUD -> Canvas -> K2_DrawLine(V[i], V[(i + 1) % numsides], 1.f, OutlineColor);
  }
}
void RotateTriangle(std::array < FVector2D, 39 > & points, float rotation) {
  const auto points_center = (points.at(0) + points.at(1) + points.at(2) + points.at(3) + points.at(4) + points.at(5) + points.at(6) +
    points.at(7) + points.at(8) + points.at(9) + points.at(10) + points.at(11) + points.at(12) + points.at(13) +
    points.at(14) + points.at(15) + points.at(16) + points.at(17) + points.at(18) + points.at(19) + points.at(20) +
    points.at(21) + points.at(22) + points.at(23) + points.at(24) + points.at(25) + points.at(26) + points.at(27) +
    points.at(28) + points.at(29) + points.at(30) + points.at(31) + points.at(32) + points.at(33) + points.at(34) +
    points.at(35) + points.at(36) + points.at(37) + points.at(38)) / 39;
  for (auto & point: points) {
    point = point - points_center;
    const auto temp_x = point.X;
    const auto temp_y = point.Y;
    const auto theta = DEG2RAD(rotation);
    const auto c = cosf(theta);
    const auto s = sinf(theta);
    point.X = temp_x * c - temp_y * s;
    point.Y = temp_x * s + temp_y * c;
    point = point + points_center;
  }
}
void * LoadFont() {
  while (!robotoFont || !robotoTinyFont || !tslFont) {
    tslFont = UObject::FindObject < UFont > ("Font TSLFont.TSLFont");
    robotoFont = UObject::FindObject < UFont > ("Font Roboto.Roboto");
    robotoTinyFont = UObject::FindObject < UFont > ("Font RobotoTiny.RobotoTiny");
    sleep(1);
  }
  return 0;
}
bool _read(kaddr addr, void * buffer, int len) {
  if (!IsValidAddress(addr)) return false;
  vm_size_t size = 0;
  kern_return_t error = vm_read_overwrite(mach_task_self(), (vm_address_t) addr, len, (vm_address_t) buffer, & size);
  if (error != KERN_SUCCESS || size != len) {
    return false;
  }
  return true;
}

bool _write(kaddr addr, void * buffer, int len) {
  if (!IsValidAddress(addr)) return false;
  kern_return_t error = vm_write(mach_task_self(), (vm_address_t) addr, (vm_offset_t) buffer, (mach_msg_type_number_t) len);
  if (error != KERN_SUCCESS) {
    return false;
  }
  return true;
}
kaddr GetRealOffset(kaddr offset) {
  if (module == 0) {
    return 0;
  }
  return (module + offset);
}
template < typename T > T Read(kaddr addr) {
  T data;
  _read(addr, reinterpret_cast < void * > ( & data), sizeof(T));
  return data;
}

#define W2S(w, s) UGameplayStatics::ProjectWorldToScreen(g_PlayerController, w, false, s)

FVector WorldToRadar(float Yaw, FVector Origin, FVector LocalOrigin, float PosX, float PosY, Vector3 Size, bool & outbuff) {
  bool flag = false;
  double num = (double) Yaw;
  double num2 = num * 0.017453292519943295;
  float num3 = (float) std::cos(num2);
  float num4 = (float) std::sin(num2);
  float num5 = Origin.X - LocalOrigin.X;
  float num6 = Origin.Y - LocalOrigin.Y;
  struct FVector Xector;
  Xector.X = (num6 * num3 - num5 * num4) / 150.f;
  Xector.Y = (num5 * num3 + num6 * num4) / 150.f;
  struct FVector Xector2;
  Xector2.X = Xector.X + PosX + Size.X / 2.f;
  Xector2.Y = -Xector.Y + PosY + Size.Y / 2.f;
  bool flag2 = Xector2.X > PosX + Size.X;
  if (flag2) {
    Xector2.X = PosX + Size.X;
  } else {
    bool flag3 = Xector2.X < PosX;
    if (flag3) {
      Xector2.X = PosX;
    }
  }
  bool flag4 = Xector2.Y > PosY + Size.Y;
  if (flag4) {
    Xector2.Y = PosY + Size.Y;
  } else {
    bool flag5 = Xector2.Y < PosY;
    if (flag5) {
      Xector2.Y = PosY;
    }
  }
  bool flag6 = Xector2.Y == PosY || Xector2.X == PosX;
  if (flag6) {
    flag = true;
  }
  outbuff = flag;
  return Xector2;
}// SAQER
void FixTriangle(float & XPos, float & YPos, int screenDist) {
  
  
  if (XPos > (screenWidth - 16)) {
    XPos = screenWidth;
    XPos -= screenDist;
  }
  
  if (XPos < 16) {
    XPos = 16;
    XPos += screenDist;
  }
  
  if (YPos > (screenHeight - 16)) {
    YPos = screenHeight;
    YPos -= screenDist;
  }
  if (YPos < 16) {
    YPos = 16;
    YPos += screenDist;
  }
}
void VectorAnglesRadar(FVector & forward, FVector & angles) {
  if (forward.X == 0.f && forward.Y == 0.f) {
    angles.X = forward.Z > 0.f ? -90.f : 90.f;
    angles.Y = 0.f;
  } else {
    angles.X = RAD2DEG(atan2(-forward.Z, forward.Size()));
    angles.Y = RAD2DEG(atan2(forward.Y, forward.X));
  }
  angles.Z = 0.f;
}
void RotateTriangle(std::array < Vector3, 3 > & points, float rotation) {
  const auto points_center = (points.at(0) + points.at(1) + points.at(2)) / 3;
  for (auto & point: points) {
    point = point - points_center;
    const auto temp_x = point.X;
    const auto temp_y = point.Y;
    const auto theta = DEG2RAD(rotation);
    const auto c = cosf(theta);
    const auto s = sinf(theta);
    point.X = temp_x * c - temp_y * s;
    point.Y = temp_x * s + temp_y * c;
    point = point + points_center;
  }
}
UGameplayStatics * iosde = (UGameplayStatics * ) UGameplayStatics::StaticClass();

static std::unordered_set < uint32_t > AlreadyChangedSet;
uintptr_t GetVirtualFunctionAddress(uintptr_t clazz, uintptr_t index) {
  if (!clazz) {
    return 0;
  }
  uintptr_t vtablePtr = * (uintptr_t * ) clazz;
  if (!vtablePtr) {
    return 0;
  }
  
  if (index < 0) {
    return 0;
  }
  return * ((uintptr_t * ) vtablePtr + index);
}
int glWidth, glHeight;
bool isInsideFOV(int x, int y) {
  if (!preferences.Config.SilentAim.Cross)
    return true;
  int circle_x = screenWidth / 2;
  int circle_y = screenHeight / 2;
  int rad = (int) preferences.Config.SilentAim.Cross * 2.0f;
  return (x - circle_x) * (x - circle_x) + (y - circle_y) * (y - circle_y) <= rad * rad;
}

auto GetTargetByCrossDist() {
  ASTExtraPlayerCharacter * result = 0;
  float max = std::numeric_limits < float > ::infinity();

  auto localPlayer = g_LocalPlayer;
  auto localController = g_PlayerController;

  if (localPlayer && localController) {
    std::vector < ASTExtraPlayerCharacter * > PlayerCharacter;
    GetAllActors(PlayerCharacter);
    for (auto actor = PlayerCharacter.begin(); actor != PlayerCharacter.end(); actor++) {
      auto Player = * actor;

      if (Player -> PlayerKey == localPlayer -> PlayerKey)
        continue;

      if (Player -> TeamID == localPlayer -> TeamID)
        continue;

      if (Player -> bDead)
        continue;

      if (Player -> bHidden) 
        continue;

      if (!Player -> Mesh) 
        continue;

      if (!Player -> RootComponent) 
        continue;

      if (preferences.Config.SilentAim.IgnoreKnocked) {
        if (Player -> Health == 0.0f)
          continue;
      }

      if (preferences.Config.SilentAim.IgnoreBot) {
        if (Player -> bEnsure)
          continue;
      }

      float dist = localPlayer -> GetDistanceTo(Player) / 100.0f;
      if (dist > g_disstance)
        continue;

      if (preferences.Config.SilentAim.VisCheck) {
        if (!localController -> LineOfSightTo(Player, {
            0,
            0,
            0
          }, true))
          continue;
      }
      auto Root = Player -> GetBonePos("Root", {});
      auto Head = Player -> GetBonePos("Head", {});

      FVector2D RootSc, HeadSc;
      if (W2S(Root, & RootSc) && W2S(Head, & HeadSc)) {
        float height = abs(HeadSc.Y - RootSc.Y);
        float width = height * 0.65f;

        FVector middlePoint = {
          HeadSc.X + (width / 2),
          HeadSc.Y + (height / 2),
          0
        };
        if ((middlePoint.X >= 0 && middlePoint.X <= (float) glWidth) &&
          (middlePoint.Y >= 0 && middlePoint.Y <= (float) glHeight)) {
          FVector2D v2Middle = FVector2D((float)(glWidth / 2), (float)(glHeight / 2));
          FVector2D v2Loc = FVector2D(middlePoint.X, middlePoint.Y);
          if (isInsideFOV((int) middlePoint.X, (int) middlePoint.Y)) {
            float distance = FVector2D::Distance(v2Middle, v2Loc);
            if (distance < max) {
              max = distance;
              result = Player;
            }
          }
        }
      }
    }
  }
  return result;
}
auto GetCurrentWeaponReplicated(ASTExtraPlayerCharacter * mode) {
  auto WeaponManagerComponent = mode -> WeaponManagerComponent;
  if (WeaponManagerComponent) {
    auto propSlot = WeaponManagerComponent -> GetCurrentUsingPropSlot();
    if ((int) propSlot.GetValue() >= 1 && (int) propSlot.GetValue() <= 3) {
      return (ASTExtraShootWeapon * ) WeaponManagerComponent -> CurrentWeaponReplicated;
    }
  }
}
void( * orig_shoot_event)(USTExtraShootWeaponComponent * thiz, FVector start, FRotator rot, void * unk1, int unk2) = 0;

void shoot_event(USTExtraShootWeaponComponent * thiz, FVector start, FRotator rot, ASTExtraShootWeapon * weapon, int unk1) {

  if (preferences.Config.SilentAim.Enable) {

    ASTExtraPlayerCharacter * Target = GetTargetByCrossDist();

    if (Target) {
      bool triggerOk = false;
      if (preferences.Config.SilentAim.Trigger !=
        JsonPreferences::EAimTrigger::None) {
        if (preferences.Config.SilentAim.Trigger ==
          JsonPreferences::EAimTrigger::Shooting) {
          triggerOk = g_LocalPlayer -> bIsWeaponFiring;
        } else if (preferences.Config.SilentAim.Trigger ==
          JsonPreferences::EAimTrigger::Scoping) {
          triggerOk = g_LocalPlayer -> bIsGunADS;
        } else if (preferences.Config.SilentAim.Trigger ==
          JsonPreferences::EAimTrigger::Both) {
          triggerOk =
            g_LocalPlayer -> bIsWeaponFiring &&
            g_LocalPlayer -> bIsGunADS;
        } else if (preferences.Config.SilentAim.Trigger ==
          JsonPreferences::EAimTrigger::Any) {
          triggerOk =
            g_LocalPlayer -> bIsWeaponFiring ||
            g_LocalPlayer -> bIsGunADS;
        }
      } else triggerOk = true;
      if (triggerOk) {

        FVector targetAimPos = Target -> GetBonePos("Head", {});
        targetAimPos.Z += 15.f;
        if (preferences.Config.SilentAim.Target == JsonPreferences::EAimTarget::Chest) {
          targetAimPos.Z -= 25.0f;
        }

        UShootWeaponEntity * ShootWeaponEntityComponent = thiz -> ShootWeaponEntityComponent;
        if (ShootWeaponEntityComponent) {
          if (preferences.Config.SilentAim.Prediction) {
            ASTExtraVehicleBase * CurrentVehicle = Target -> CurrentVehicle;
            if (CurrentVehicle) {
              FVector LinearVelocity = CurrentVehicle -> ReplicatedMovement.LinearVelocity;
// SAQER
              float dist = FVector::Distance(g_LocalPlayer -> GetBonePos("Root", {}), Target -> GetBonePos("Root", {}));
              auto timeToTravel = dist / ShootWeaponEntityComponent -> BulletRange;

              targetAimPos = UKismetMathLibrary::Add_VectorVector(targetAimPos, UKismetMathLibrary::Multiply_VectorFloat(LinearVelocity, timeToTravel));
            } else {
              FVector LinearVelocity = CurrentVehicle -> ReplicatedMovement.LinearVelocity;

              float dist = FVector::Distance(g_LocalPlayer -> GetBonePos("Root", {}), Target -> GetBonePos("Root", {}));
              auto timeToTravel = dist / ShootWeaponEntityComponent -> BulletRange;

              targetAimPos = UKismetMathLibrary::Add_VectorVector(targetAimPos, UKismetMathLibrary::Multiply_VectorFloat(LinearVelocity, timeToTravel));

            }
          }

          FVector fDir = UKismetMathLibrary::Subtract_VectorVector(targetAimPos, g_PlayerController -> PlayerCameraManager -> CameraCache.POV.Location);
          rot = UKismetMathLibrary::Conv_VectorToRotator(fDir);
// SAQER
        }
      }
    }
  }
  return orig_shoot_event(thiz, start, rot, weapon, unk1);
}

void RenderESP(AHUD * HUD, int ScreenWidth, int ScreenHeight) {
  ASTExtraPlayerCharacter * localPlayer = 0;
  ASTExtraPlayerController * localPlayerController = 0;
  glWidth = ScreenWidth;
  glHeight = ScreenHeight;
  UCanvas * Canvas = HUD -> Canvas;
  if (Canvas) {

    static bool loadFont = false;
    if (!loadFont) {
      LoadFont();
      loadFont = true;
    }

    
    if (!robotoFont || !tslFont || !robotoTinyFont)
      return;
    tslFont -> LegacyFontSize = 25;
    std::wstring name = L"S A Q E R";
    DrawTextcan(HUD, FString(name), {
      (float) screenWidth / 2,
      80
    }, COLOR_WHITE, COLOR_BLACK);
    UGameplayStatics * gGameplayStatics = (UGameplayStatics * ) UGameplayStatics::StaticClass();
    auto Actors = getActors();

    auto GWorld = GetFullWorld();
    if (GWorld) {
      UNetDriver * NetDriver = GWorld -> NetDriver;
      if (NetDriver) {
        UNetConnection * ServerConnection = NetDriver -> ServerConnection;
        if (ServerConnection) {
          localPlayerController = (ASTExtraPlayerController * ) ServerConnection -> PlayerController;
        }
      }

      if (localPlayerController) {
        localPlayerController -> AntiCheatManagerComp = 0;
        localPlayerController -> bShouldReportAntiCheat = false;
        localPlayerController -> CheatClass = 0;
        localPlayerController -> CheatManager = 0;

        std::vector < ASTExtraPlayerCharacter * > PlayerCharacter;
        GetAllActors(PlayerCharacter);
        for (auto actor = PlayerCharacter.begin(); actor != PlayerCharacter.end(); actor++) {
          auto Actor = * actor;

          if (Actor -> PlayerKey ==
            ((ASTExtraPlayerController * ) localPlayerController) -> PlayerKey) {
            localPlayer = Actor;
            break;
          }
        }

        {
          if (localPlayer) {
            if (WideView) {
              auto ThirdPersonCameraComponent = localPlayer -> ThirdPersonCameraComponent;
              if (ThirdPersonCameraComponent) {
                *(float * )((uintptr_t) & ThirdPersonCameraComponent -> OrthoWidth - sizeof(float)) = WideValue;
              }
            }
            auto WeaponManagerComponent = localPlayer -> WeaponManagerComponent;

            if (preferences.Config.SilentAim.AimBot) {
              ASTExtraPlayerCharacter * Target = GetTargetByCrossDist();

              if (Target && Target -> RootComponent) {

                bool triggerOk = false;
                if (preferences.Config.SilentAim.Trigger !=
                  JsonPreferences::EAimTrigger::None) {
                  if (preferences.Config.SilentAim.Trigger ==
                    JsonPreferences::EAimTrigger::Shooting) {
                    triggerOk = localPlayer -> bIsWeaponFiring;
                  } else if (preferences.Config.SilentAim.Trigger ==
                    JsonPreferences::EAimTrigger::Scoping) {
                    triggerOk = localPlayer -> bIsGunADS;
                  } else if (preferences.Config.SilentAim.Trigger ==
                    JsonPreferences::EAimTrigger::Both) {
                    triggerOk =
                      localPlayer -> bIsWeaponFiring &&
                      localPlayer -> bIsGunADS;
                  } else if (preferences.Config.SilentAim.Trigger ==
                    JsonPreferences::EAimTrigger::Any) {
                    triggerOk =
                      localPlayer -> bIsWeaponFiring ||
                      localPlayer -> bIsGunADS;
                  }
                } else triggerOk = true;
                if (triggerOk) {
                  FVector targetAimPos;
                  if (preferences.Config.SilentAim.Target ==
                    JsonPreferences::EAimTarget::Head) {
                    targetAimPos = Target -> GetBonePos("Head", {});
                  }
                  if (preferences.Config.SilentAim.Target ==
                    JsonPreferences::EAimTarget::Chest) {
                    targetAimPos = Target -> GetBonePos("pelvis", {});
                  }
                  if (preferences.Config.SilentAim.ReCo) {
                    if (g_LocalPlayer -> bIsGunADS) {
                      if (g_LocalPlayer -> bIsWeaponFiring) {
                        float dist = g_LocalPlayer -> GetDistanceTo(Target) / 100.f;
                        targetAimPos.Z -= dist * preferences.Config.SilentAim.Recc;
                      }
                    }
                  }
                  if (WeaponManagerComponent) {
                    auto propSlot = WeaponManagerComponent -> GetCurrentUsingPropSlot();
                    if ((int) propSlot.GetValue() >= 1 &&
                      (int) propSlot.GetValue() <= 3) {
                      auto CurrentWeaponReplicated = (ASTExtraShootWeapon * ) WeaponManagerComponent -> CurrentWeaponReplicated;
                      if (CurrentWeaponReplicated) {
                        auto ShootWeaponComponent = CurrentWeaponReplicated -> ShootWeaponComponent;
                        if (ShootWeaponComponent) {
                          UShootWeaponEntity * ShootWeaponEntityComponent = ShootWeaponComponent -> ShootWeaponEntityComponent;
                          if (ShootWeaponEntityComponent) {
                            if (preferences.Config.SilentAim.Prediction) {
                              ASTExtraVehicleBase * CurrentVehicle = Target -> CurrentVehicle;
                              if (CurrentVehicle) {
                                FVector LinearVelocity = CurrentVehicle -> ReplicatedMovement.LinearVelocity;
                                float dist = localPlayer -> GetDistanceTo(
                                  Target);
                                auto timeToTravel = dist /
                                  ShootWeaponEntityComponent -> BulletRange;
                                targetAimPos = UKismetMathLibrary::Add_VectorVector(
                                  targetAimPos,
                                  UKismetMathLibrary::Multiply_VectorFloat(
                                    LinearVelocity,
                                    timeToTravel));
                              } else {
                                FVector Velocity = Target -> GetVelocity();
                                float dist = localPlayer -> GetDistanceTo(
                                  Target);
                                auto timeToTravel = dist /
                                  ShootWeaponEntityComponent -> BulletRange;

                                targetAimPos = UKismetMathLibrary::Add_VectorVector(
                                  targetAimPos,
                                  UKismetMathLibrary::Multiply_VectorFloat(
                                    Velocity,
                                    timeToTravel));
                              }
                            }
                            localPlayerController -> SetControlRotation(
                              ToRotator(
                                localPlayerController -> PlayerCameraManager -> CameraCache.POV.Location,
                                targetAimPos), "");
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            if (preferences.Config.SilentAim.Enable) {
              auto WeaponManagerComponent = localPlayer -> WeaponManagerComponent;
              if (WeaponManagerComponent) {
                auto propSlot = WeaponManagerComponent -> GetCurrentUsingPropSlot();
                if ((int) propSlot.GetValue() >= 1 && (int) propSlot.GetValue() <= 3) {
                  auto CurrentWeaponReplicated = (ASTExtraShootWeapon * ) WeaponManagerComponent -> CurrentWeaponReplicated;
                  if (CurrentWeaponReplicated) {
                    auto ShootWeaponComponent = CurrentWeaponReplicated -> ShootWeaponComponent;
                    if (ShootWeaponComponent) {
                      int shoot_event_idx = 174;
                      auto VTable = (void ** ) ShootWeaponComponent -> VTable;
                      if (VTable && (VTable[shoot_event_idx] != shoot_event)) {
                        orig_shoot_event = decltype(orig_shoot_event)(
                          VTable[shoot_event_idx]);
                        VTable[shoot_event_idx] = (void * ) shoot_event;
                      }
                    }
                  }
                }
              }
            }
            if (preferences.Config.SilentAim.Enable || preferences.Config.SilentAim.AimBot) {
              DrawCircle(HUD, ScreenWidth / 2, ScreenHeight / 2, preferences.Config.SilentAim.Cross, 100, COLOR_RED);
            }

            int totalEnemies = 0, totalBots = 0;
            std::vector < ASTExtraPlayerCharacter * > PlayerCharacter;
            GetAllActors(PlayerCharacter);
            for (auto actor = PlayerCharacter.begin(); actor != PlayerCharacter.end(); actor++) {
              auto Player = * actor;

              if (Player -> PlayerKey == localPlayer -> PlayerKey)
                continue;

              if (Player -> TeamID == localPlayer -> TeamID)
                continue;

              if (Player -> bDead)
                continue;

              if (Player -> bHidden)
                continue;

              
              

              if (!Player -> RootComponent)
                continue;

              if (Config.ESPMenu.IgnoreBot) {
                if (Player -> bEnsure)
                  continue;
              }

              if (Player -> bEnsure)
                totalBots++;
              else totalEnemies++;

              FVector Head = GetBoneLocationByName(Player, "Head");
              Head.Z += 12.5f;
              FVector Root = GetBoneLocationByName(Player, "Root");
              FVector upper_r = GetBoneLocationByName(Player, "upperarm_r");
              FVector lowerarm_r = GetBoneLocationByName(Player, "lowerarm_r");
              FVector hand_r = GetBoneLocationByName(Player, "hand_r");
              FVector upper_l = GetBoneLocationByName(Player, "upperarm_l");
              FVector lowerarm_l = GetBoneLocationByName(Player, "lowerarm_l");
              FVector hand_l = GetBoneLocationByName(Player, "hand_l");
              FVector thigh_l = GetBoneLocationByName(Player, "thigh_l");// SAQER
              FVector calf_l = GetBoneLocationByName(Player, "calf_l");
              FVector foot_l = GetBoneLocationByName(Player, "foot_l");
              FVector thigh_r = GetBoneLocationByName(Player, "thigh_r");
              FVector calf_r = GetBoneLocationByName(Player, "calf_r");
              FVector foot_r = GetBoneLocationByName(Player, "foot_r");
              FVector neck_01 = GetBoneLocationByName(Player, "neck_01");
              FVector pelvis = GetBoneLocationByName(Player, "pelvis");

              float Distance = Player -> GetDistanceTo(localPlayer) / 100.f;
              if (Distance < 500.f) {
                if (Config.ESPMenu.Alert) {
                  bool Useless = false;
                  FVector2D EntityPos = WorldToRadar(localPlayer -> K2_GetActorRotation().Yaw, Head, localPlayer -> GetHeadLocation(true), NULL, NULL, FVector((float) screenWidth, (float) screenHeight, 0.f), Useless);
                  float radar_range = 270.f;
                  FVector angle;
                  FVector MiddlePoint(((float) screenWidth / 2.f) - EntityPos.X, ((float) screenHeight / 2.f) - EntityPos.Y, 0.f);
                  VectorAnglesRadar(MiddlePoint, angle);
                  const auto AngleYawRadian = DEG2RAD(angle.Y + 180.f);
                  float Point_X = ((float) screenWidth / 2.f) + (radar_range) / 2.f * 8.f * cosf(AngleYawRadian);
                  float Point_Y = ((float) screenHeight / 2.f) + (radar_range) / 2.f * 8.f * sinf(AngleYawRadian);
                  FixTriangle(Point_X, Point_Y, 100);
                  std::array < FVector2D, 39 > points {
                    FVector2D((float) Point_X - (5.6f * (float) 3.f), Point_Y - (7.3f * 3.f)),
                      FVector2D((float) Point_X + (11.6f * 3.f), Point_Y),
                      FVector2D((float) Point_X - (5.6f * 3.f), Point_Y + (7.3f * 3.f)),
                      FVector2D((float) Point_X - (5.6f * 3.f), Point_Y - (4.3f * 3.f)),
                      FVector2D((float) Point_X - (19.5f * 3.f), Point_Y - (4.3f * 3.f)),
                      FVector2D((float) Point_X - (19.5f * 3.f), Point_Y + (4.3f * 3.f)),
                      FVector2D((float) Point_X - (5.6f * 3.f), Point_Y + (4.3f * 3.f)),
                      FVector2D((float) Point_X + (10.3f * 3.f), Point_Y),
                      FVector2D((float) Point_X - (5.f * 3.f), Point_Y - (3.f * 3.f)),
                      FVector2D((float) Point_X - (5.f * 3.f), Point_Y + (3.f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y - (6.5f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y - (5.5f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y - (3.f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y - (3.f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y - (2.5f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y - (1.5f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y - (0.5f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y + (6.5f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y + (5.5f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y + (3.f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y + (3.f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y + (2.5f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y + (1.5f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y + (0.2f * 3.f)),
                      FVector2D((float) Point_X - (5.f * (float) 3.f), Point_Y - (0.2f * 3.f)),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y - (3.75f * 3.f)),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y - (3.f * 3.f)),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y - (2.f * 3.f)),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y - (1.f * 3.f)),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y - (0.5f * 3.f)),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y - (0.2f * 3.f)),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y + (3.75f * 3.f)),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y + (3.f * 3.f)),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y + (2.f * 3.f)),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y + (1.f * 3.f)),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y + (0.5f * 3.f)),
                      FVector2D((float) Point_X - (18.5f * 3.f), Point_Y + (0.2f * 3.f)),
                  };
                  FVector2D BelowRoowwtSc;
                  if (gGameplayStatics -> ProjectWorldToScreen(localPlayerController, Head, false, & BelowRoowwtSc)) {} else {
                    RotateTriangle(points, angle.Y + 180.0f);
                    float Thickness = 3.f;

                    

                    bool IsVisible = localPlayerController -> LineOfSightTo(
                      Player, {
                        0,
                        0,
                        0
                      },
                      true);

                    if (Player -> bEnsure) {// SAQER
                      DrawArrows(HUD, points, Thickness, COLOR_WHITE); 
                    } else {

                      if (IsVisible) {

                        DrawArrows(HUD, points, Thickness, COLOR_GREEN);
                      } else {

                        DrawArrows(HUD, points, Thickness, COLOR_RED);
                      }

                    }
                  }
                }
                FVector2D HeadSc, RootSc, upper_rPoSC, lowerarm_rPoSC, hand_rPoSC, upper_lPoSC, hand_lPoSC, thigh_lPoSC, calf_lPoSC, foot_lPoSC, thigh_rPoSC, calf_rPoSC, foot_rPoSC, neck_01PoSC, pelvisPoSC, lowerarm_lSC;
                if (gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    Head, false, & HeadSc) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    upper_r, false, &
                    upper_rPoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    upper_l, false, &
                    upper_lPoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    lowerarm_r, false, &
                    lowerarm_rPoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    hand_r, false, &
                    hand_rPoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    lowerarm_l, false, &
                    lowerarm_lSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    hand_l, false, &
                    hand_lPoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    thigh_l, false, &
                    thigh_lPoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    calf_l, false, &
                    calf_lPoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    foot_l, false, &
                    foot_lPoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    thigh_r, false, &
                    thigh_rPoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    calf_r, false, &
                    calf_rPoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    foot_r, false, &
                    foot_rPoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    neck_01, false, &
                    neck_01PoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    pelvis, false, &
                    pelvisPoSC) &&
                  gGameplayStatics -> ProjectWorldToScreen(
                    localPlayerController,
                    Root, false, & RootSc)) {

                  bool IsVisible = localPlayerController -> LineOfSightTo(
                    Player, {
                      0,
                      0,
                      0
                    },
                    true);
                  FLinearColor Color = {
                    1.0f,
                    0,
                    0,
                    1.0f
                  };
                  if (IsVisible)
                    Color = {
                      0,
                      1.0f,
                      0,
                      1.0f
                    };
                  
                  if (Config.ESPMenu.Line) {

                    FVector screenPos = localPlayerController -> PlayerCameraManager -> GetCameraLocation();
                    screenPos.Z += 350.0f;
                    screenPos.Y += 350.0f;
                    screenPos.X += 350.0f;
                    if (!localPlayerController -> LineOfSightTo(Player, screenPos, true)) {

                      DrawLine(HUD, {
                        static_cast < float > (screenWidth / 2),
                        0
                      }, {
                        HeadSc.X,
                        HeadSc.Y - 50
                      }, 1.0f, COLOR_RED);

                      if (Player -> bEnsure) {
                        DrawLine(HUD, {
                          static_cast < float > (screenWidth / 2),
                          0
                        }, {
                          HeadSc.X,
                          HeadSc.Y - 50
                        }, 1.0f, COLOR_YELLOW);
                      }
                    } else {

                      DrawLine(HUD, {
                        static_cast < float > (screenWidth / 2),
                        0
                      }, {
                        HeadSc.X,
                        HeadSc.Y - 50
                      }, 1.0f, COLOR_LIME);

                      if (Player -> bEnsure) {
                        DrawLine(HUD, {
                          static_cast < float > (screenWidth / 2),
                          0
                        }, {
                          HeadSc.X,
                          HeadSc.Y - 50
                        }, 1.0f, COLOR_WHITE);
                      }

                    }

                  }
                  
                  if (Config.ESPMenu.Skeleton) {
                    static vector < string > right_arm {
                      "spine_03",
                      "clavicle_r",
                      "upperarm_r",
                      "lowerarm_r",
                      "hand_r",
                      "item_r"
                    };
                    static vector < string > left_arm {
                      "spine_03",
                      "clavicle_l",
                      "upperarm_l",
                      "lowerarm_l",
                      "hand_l",
                      "item_l"
                    };
                    static vector < string > spine {
                      "Head",
                      "neck_01",
                      "spine_03",
                      "spine_02",
                      "spine_01",
                      "pelvis"
                    };
                    static vector < string > lower_right {
                      "pelvis",
                      "thigh_r",
                      "calf_r",
                      "foot_r"
                    };
                    static vector < string > lower_left {
                      "pelvis",
                      "thigh_l",
                      "calf_l",
                      "foot_l"
                    };
                    static vector < vector < string >> skeleton {
                      right_arm,
                      left_arm,
                      spine,
                      lower_right,
                      lower_left
                    };
                    for (auto & boneStructure: skeleton) {
                      string lastBone;
                      for (string & currentBone: boneStructure) {
                        if (!lastBone.empty()) {
                          FVector wBoneFrom = GetBoneLocationByName(Player, lastBone.c_str());
                          FVector wBoneTo = GetBoneLocationByName(Player, currentBone.c_str());
                          FVector2D boneFrom, boneTo;
                          if (gGameplayStatics -> ProjectWorldToScreen(localPlayerController, wBoneFrom, false, & boneFrom) && gGameplayStatics -> ProjectWorldToScreen(localPlayerController, wBoneTo, false, & boneTo)) {
                            bool IsVisibles = g_PlayerController -> LineOfSightTo(g_PlayerController -> PlayerCameraManager, Player -> GetBonePos(currentBone.c_str(), {}), true);
                            if (IsVisibles) {
                              if (Player -> bEnsure) {
                                DrawLine(HUD, boneFrom, boneTo, EspSktonThik, COLOR_LIME);
                                
                              } else {
                                DrawLine(HUD, boneFrom, boneTo, EspSktonThik, COLOR_LIME);
                                
                              }
                            } else {
                              if (Player -> bEnsure) {
                                DrawLine(HUD, boneFrom, boneTo, EspSktonThik, COLOR_WHITE);
                                
                              } else {
                                DrawLine(HUD, boneFrom, boneTo, EspSktonThik, COLOR_RED);
                                
                              }
                            }

                          }
                        }
                        lastBone = currentBone;
                      }
                    }
                  }

                  if (Config.ESPMenu.Box) {
                    float boxHeight = abs(HeadSc.Y - RootSc.Y);
                    float boxWidth = boxHeight * 0.65f;
                    FVector2D vBox = FVector2D(HeadSc.X - (boxWidth / 2), HeadSc.Y);
                    Box4Line(HUD, 1.5f, vBox.X, vBox.Y, boxWidth, boxHeight, COLOR_WHITE);
                  }
                  
                  if (Config.ESPMenu.Health) {
                    int CurHP = (int) std::max(0, std::min((int) Player -> Health, (int) Player -> HealthMax));
                    int MaxHP = (int) Player -> HealthMax;

                    if (Player -> Health == 0.0f && !Player -> bDead) {
                      CurHP = Player -> NearDeathBreath;
                      if (Player -> NearDeatchComponent) {
                        MaxHP = Player -> NearDeatchComponent -> BreathMax;
                      }
                    }

                    
                    auto mWidth = 158.0f;
                    auto mHeight = 3.0f;
                    HeadSc.X -= (mWidth / 2);
                    HeadSc.Y -= (mHeight * 1.5f);

                    DrawFilledRectangle(HUD, {
                      HeadSc.X,
                      HeadSc.Y - 10
                    }, (CurHP * mWidth / MaxHP), mHeight, {
                      1.0f,
                      1.0f,
                      1.0f,
                      0.8f
                    });

                    if (Player -> TeamID == 1 || Player -> TeamID == 21 || Player -> TeamID == 31 || Player -> TeamID == 41 || Player -> TeamID == 51 || Player -> TeamID == 61 || Player -> TeamID == 71 || Player -> TeamID == 81 || Player -> TeamID == 91 || Player -> TeamID == 101 || Player -> TeamID == 111 || Player -> TeamID == 121 || Player -> TeamID == 131 || Player -> TeamID == 141 || Player -> TeamID == 151 || Player -> TeamID == 161 || Player -> TeamID == 171 || Player -> TeamID == 181 || Player -> TeamID == 191 || Player -> TeamID == 201 || Player -> TeamID == 211) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.85f,
                        0.33f,
                        0.84f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 2 || Player -> TeamID == 22 || Player -> TeamID == 32 || Player -> TeamID == 42 || Player -> TeamID == 52 || Player -> TeamID == 62 || Player -> TeamID == 72 || Player -> TeamID == 82 || Player -> TeamID == 92 || Player -> TeamID == 102 || Player -> TeamID == 112 || Player -> TeamID == 122 || Player -> TeamID == 132 || Player -> TeamID == 142 || Player -> TeamID == 152 || Player -> TeamID == 162 || Player -> TeamID == 172 || Player -> TeamID == 182 || Player -> TeamID == 192 || Player -> TeamID == 202 || Player -> TeamID == 212) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.62f,
                        0.12f,
                        0.94f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 3 || Player -> TeamID == 23 || Player -> TeamID == 33 || Player -> TeamID == 43 || Player -> TeamID == 53 || Player -> TeamID == 63 || Player -> TeamID == 73 || Player -> TeamID == 83 || Player -> TeamID == 93 || Player -> TeamID == 103 || Player -> TeamID == 113 || Player -> TeamID == 123 || Player -> TeamID == 133 || Player -> TeamID == 143 || Player -> TeamID == 153 || Player -> TeamID == 163 || Player -> TeamID == 173 || Player -> TeamID == 183 || Player -> TeamID == 193 || Player -> TeamID == 203 || Player -> TeamID == 213) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.0f,
                        1.0f,
                        0.5f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 4 || Player -> TeamID == 24 || Player -> TeamID == 34 || Player -> TeamID == 44 || Player -> TeamID == 54 || Player -> TeamID == 64 || Player -> TeamID == 74 || Player -> TeamID == 84 || Player -> TeamID == 94 || Player -> TeamID == 104 || Player -> TeamID == 114 || Player -> TeamID == 124 || Player -> TeamID == 134 || Player -> TeamID == 144 || Player -> TeamID == 154 || Player -> TeamID == 164 || Player -> TeamID == 174 || Player -> TeamID == 184 || Player -> TeamID == 194 || Player -> TeamID == 204 || Player -> TeamID == 214) {
// SAQER
                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.53f,
                        0.8f,
                        0.92f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 5 || Player -> TeamID == 25 || Player -> TeamID == 35 || Player -> TeamID == 45 || Player -> TeamID == 55 || Player -> TeamID == 65 || Player -> TeamID == 75 || Player -> TeamID == 85 || Player -> TeamID == 95 || Player -> TeamID == 105 || Player -> TeamID == 115 || Player -> TeamID == 125 || Player -> TeamID == 135 || Player -> TeamID == 145 || Player -> TeamID == 155 || Player -> TeamID == 165 || Player -> TeamID == 175 || Player -> TeamID == 185 || Player -> TeamID == 195 || Player -> TeamID == 205 || Player -> TeamID == 215) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.0f,
                        1.0f,
                        1.0f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 6 || Player -> TeamID == 26 || Player -> TeamID == 36 || Player -> TeamID == 46 || Player -> TeamID == 56 || Player -> TeamID == 66 || Player -> TeamID == 76 || Player -> TeamID == 86 || Player -> TeamID == 96 || Player -> TeamID == 106 || Player -> TeamID == 116 || Player -> TeamID == 126 || Player -> TeamID == 136 || Player -> TeamID == 146 || Player -> TeamID == 156 || Player -> TeamID == 166 || Player -> TeamID == 176 || Player -> TeamID == 186 || Player -> TeamID == 196 || Player -> TeamID == 206 || Player -> TeamID == 216) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.12f,
                        0.56f,
                        1.0f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 7 || Player -> TeamID == 27 || Player -> TeamID == 37 || Player -> TeamID == 47 || Player -> TeamID == 57 || Player -> TeamID == 67 || Player -> TeamID == 77 || Player -> TeamID == 87 || Player -> TeamID == 97 || Player -> TeamID == 107 || Player -> TeamID == 117 || Player -> TeamID == 127 || Player -> TeamID == 137 || Player -> TeamID == 147 || Player -> TeamID == 157 || Player -> TeamID == 167 || Player -> TeamID == 177 || Player -> TeamID == 187 || Player -> TeamID == 197 || Player -> TeamID == 207 || Player -> TeamID == 217) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        1.0f,
                        0.0f,
                        1.0f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 8 || Player -> TeamID == 18 || Player -> TeamID == 28 || Player -> TeamID == 38 || Player -> TeamID == 48 || Player -> TeamID == 58 || Player -> TeamID == 68 || Player -> TeamID == 78 || Player -> TeamID == 88 || Player -> TeamID == 98 || Player -> TeamID == 108 || Player -> TeamID == 118 || Player -> TeamID == 128 || Player -> TeamID == 138 || Player -> TeamID == 148 || Player -> TeamID == 158 || Player -> TeamID == 168 || Player -> TeamID == 178 || Player -> TeamID == 188 || Player -> TeamID == 198 || Player -> TeamID == 208 || Player -> TeamID == 218) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.16f,
                        0.14f,
                        0.13f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 9 || Player -> TeamID == 19 || Player -> TeamID == 29 || Player -> TeamID == 39 || Player -> TeamID == 49 || Player -> TeamID == 59 || Player -> TeamID == 69 || Player -> TeamID == 79 || Player -> TeamID == 89 || Player -> TeamID == 99 || Player -> TeamID == 109 || Player -> TeamID == 119 || Player -> TeamID == 129 || Player -> TeamID == 139 || Player -> TeamID == 149 || Player -> TeamID == 159 || Player -> TeamID == 169 || Player -> TeamID == 179 || Player -> TeamID == 189 || Player -> TeamID == 199 || Player -> TeamID == 209 || Player -> TeamID == 219) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        1.0f,
                        0.5f,
                        0.31f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 10) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.42f,
                        0.35f,
                        0.8f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 11) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.5f,
                        1.0f,
                        0.8f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 12) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.25f,
                        0.41f,
                        0.88f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 13) {// SAQER

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        1.0f,
                        0.5f,
                        0.0f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 14) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.94f,
                        0.9f,
                        0.5f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 15) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.75f,
                        0.75f,
                        0.75f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 16) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        1.0f,
                        0.92f,
                        0.8f,
                        0.4f
                      });

                    } else if (Player -> TeamID == 17) {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.89f,
                        0.09f,
                        0.05f,
                        0.4f
                      });

                    } else {

                      DrawFilledRectangle(HUD, {
                        HeadSc.X,
                        HeadSc.Y - 32
                      }, mWidth, 22.0f, {
                        0.89f,
                        0.09f,
                        0.05f,
                        0.4f
                      });

                    }

                  }

                  
                  if (Config.ESPMenu.Weapon) {
                    

                    auto WeaponManagerComponent = Player -> WeaponManagerComponent;// SAQER
                    if (WeaponManagerComponent) {
                      {
                        auto CurrentWeaponReplicated = (ASTExtraShootWeapon * ) WeaponManagerComponent -> CurrentWeaponReplicated;
                        if (CurrentWeaponReplicated) {
                          auto WeaponId = (int) CurrentWeaponReplicated -> GetWeaponID();
                          if (WeaponId) {

                            std::wstring s;
                            s += CurrentWeaponReplicated -> GetWeaponName().ToWString();
                            robotoFont -> LegacyFontSize = 10.0f;
                            DrawOutlinedText(HUD, FString(s), FVector2D(RootSc.X, (HeadSc.Y - 41)), FLinearColor(1.0, 0.4980392156862745, 0.0, 1.0), COLOR_BLACK, true);
                          }
                        }
                      }
                    }

                  }

                  
                  if (Config.ESPMenu.Name) {
                    robotoFont -> LegacyFontSize = 10.f;
                    std::wstring knockedstr = L"[ Knocked ]";

                    std::wstring Text;

                    if (Player -> bEnsure) {
                      Text = L"BOT";
                    } else {
                      Text = std::to_wstring(Player -> TeamID) + L"  " + Player -> PlayerName.ToWString();
                    }

                    

                    if (Player -> Health <= 0) {
                      if (Player -> bEnsure) {
                        DrawOutlinedText(HUD, FString(knockedstr), FVector2D(RootSc.X - 1, (RootSc.Y + 3)), COLOR_PLAYER, COLOR_BLACK, true);
                      } else {
                        DrawOutlinedText(HUD, FString(knockedstr), FVector2D(RootSc.X - 1, (RootSc.Y + 3)), FLinearColor(255 / 255.0f, 0 / 255.0f, 0 / 255.0f, 1.0f), COLOR_BLACK, true);
                      }
                    } else {
                      if (!Player -> bEnsure) {
                        DrawOutlinedText(HUD, FString(Text), FVector2D(RootSc.X - 13, (HeadSc.Y - 21)), COLOR_WHITE, COLOR_BLACK, true);
                      } else {

                        DrawOutlinedText(HUD, FString(Text), FVector2D(RootSc.X - 13, (HeadSc.Y - 21)), COLOR_WHITE, COLOR_BLACK, true);
                      }
                    }
                  }
                  if (Config.ESPMenu.Distance) {
                    std::wstring distance;
                    distance = std::to_wstring((int) Distance) + L" M";
                    robotoFont -> LegacyFontSize = 11.f;
                    DrawOutlinedText(HUD, FString(distance), FVector2D(RootSc.X - 1, (RootSc.Y + 17)), COLOR_WHITE, COLOR_BLACK, true);

                  }
                }
              }
            }

            if (totalEnemies > 0 || totalBots > 0) {
              std::wstring numi = L"Players: " + std::to_wstring(totalEnemies) +
                L" (Bots: " + std::to_wstring(totalBots) + L" )";
              tslFont -> LegacyFontSize = 20;
              DrawTextcan(HUD, FString(numi), {
                  (float) screenWidth / 2,
                  120
                },
                COLOR_RED, COLOR_BLACK);
            }
          }
        }
      }
      g_LocalPlayer = localPlayer;
      g_PlayerController = localPlayerController;
    }
  }
}

std::wstring NStoWS(NSString * Str) {
  NSStringEncoding pEncode = CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingUTF32LE);
  NSData * pSData = [Str dataUsingEncoding: pEncode];// SAQER
  return std::wstring((wchar_t * )[pSData bytes], [pSData length] / sizeof(wchar_t));
}
NSString * WStoNS(const std::wstring & Str) {
  NSString * pString = [
    [NSString alloc]
    initWithBytes: (char * ) Str.data()
    length: Str.size() * sizeof(wchar_t)
    encoding: CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingUTF32LE)
  ];
  return pString;
}

void * ( * oProcessEvent)(UObject * pObj, UFunction * pFunc, void * pArgs);
void * hkProcessEvent(UObject * pObj, UFunction * pFunc, void * pArgs) {
  if (pFunc) {
    if (pFunc -> GetFullName() == ("Function Engine.HUD.ReceiveDrawHUD")) {
      AHUD * pHUD = (AHUD * ) pObj;
      if (pHUD) {
        auto Params = (AHUD_ReceiveDrawHUD_Params * ) pArgs;
        if (Params) {
          RenderESP(pHUD, Params -> SizeX, Params -> SizeY);
          screenWidth = Params -> SizeX;
          screenHeight = Params -> SizeY;
        }
      }
    }
  }
  return oProcessEvent(pObj, pFunc, pArgs);
}

void * RTL_language() {

  auto MAIN = (FUObjectArray * )(obbbbl());
  auto gobjects = MAIN -> ObjObjects;
  for (int i = 0; i < gobjects.Num(); i++)
    if (auto obj = gobjects.GetByIndex(i)) {

      if (obj -> IsA(AHUD::StaticClass())) {
        auto HUD = (AHUD * ) obj;
        int its = 76;
        auto VTable = (void ** ) HUD -> VTable;
        if (VTable && (VTable[its] != hkProcessEvent)) {
          oProcessEvent = decltype(oProcessEvent)(VTable[its]);
          VTable[its] = (void * ) hkProcessEvent;
        }
      }
      if (obj -> IsA(ASTExtraPlayerController::StaticClass())) {
        auto HUD = (ASTExtraPlayerController * ) obj;
        int its = 76;
        auto VTable = (void ** ) HUD -> VTable;
        if (VTable && (VTable[its] != hkProcessEvent)) {
          oProcessEvent = decltype(oProcessEvent)(VTable[its]);
          VTable[its] = (void * ) hkProcessEvent;
        }
      }
    }// SAQER
  return 0;
}

#define hook GaYSSS9aAL

#define hook GaYSSS9aAL

  +
  (void) load {
    FName::GNames = GetGNames();
    while (!FName::GNames) {
      FName::GNames = GetGNames();
      sleep(1);
    }

    UObject::GUObjectArray = (FUObjectArray * )(obbbbl());

    while (!UObject::GUObjectArray) {
      UObject::GUObjectArray = (FUObjectArray * )(obbbbl());
      sleep(1);
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^ {

      
      [self load1];

    });
  } +
  (void) load1 {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^ {
      RTL_language();
    });
  }
__attribute__((constructor)) void _init() {
  pthread_t t;

  
  
}

@end
