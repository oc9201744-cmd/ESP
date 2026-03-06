//
//  ImGuiLoad.h
//  libPUBGDylib
//
//  Created by yiming on 2021/5/31.
//
//#import "KittyMemory/MemoryPatch.hpp"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN


@interface ImGuiLoad : NSObject
+ (instancetype)share;

- (void)show;
- (void)initTapGes;
@end

NS_ASSUME_NONNULL_END
// SAQER