#import "PubgLoad.h"
#import "metalbiew.h"
extern bool MenDeal;
//  Created by Telegram @CheatBot_Owner
@interface ImGuiLoad()
@property (nonatomic, strong) metalbiew *vna;
@end

@implementation ImGuiLoad

+ (void)load
{
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        //  Created by Telegram @CheatBot_Owner
        // [[self share] show];
        [[self share] initTapGes];
    });
}


+ (instancetype)share
{
    static ImGuiLoad *tool;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        tool = [[ImGuiLoad alloc] init];
    });
    return tool;
}
-(void)initTapGes
{
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] init];
    tap.numberOfTapsRequired = 3;//点击次数
    tap.numberOfTouchesRequired = 3;//手指数
    [[UIApplication sharedApplication].windows[0].rootViewController.view addGestureRecognizer:tap];
    [tap addTarget:self action:@selector(show)];
}
- (void)show
{
    if (!_vna) {
        metalbiew *vc = [[metalbiew alloc] init];
        _vna = vc;
    }
    if(MenDeal==true)MenDeal=false;
    else {
        MenDeal=true;
        [[UIApplication sharedApplication].windows[0].rootViewController.view addSubview:_vna.view];}
    
}



@end
