#import <UIKit/UIKit.h>
#include <stdio.h>
#include <unistd.h>

// UIKit calls these entry points on the main thread. A fresh file per launch
// keeps time bases separate. Write to the app container for offline collection.
static FILE *probeLog;
static unsigned long eventNumber;
static void record(NSString *line) {
    double now = NSProcessInfo.processInfo.systemUptime;
    fprintf(probeLog ?: stderr, "%.6f %s\n", now, line.UTF8String);
}

static NSString *labelFor(UIView *v) {
    if (!v) return @"nil";
    return [NSString stringWithFormat:@"%@/%@", NSStringFromClass(v.class),
            v.accessibilityIdentifier ?: @"-"];
}

@interface TPApplication : UIApplication
@end
@implementation TPApplication
- (void)sendEvent:(UIEvent *)event {
    if (event.type == UIEventTypeTouches) {
        ++eventNumber;
        NSSet *all = event.allTouches;
        record([NSString stringWithFormat:@"app seq=%lu eventTime=%.6f all=%lu nil=%d appState=%ld",
                eventNumber, event.timestamp, (unsigned long)all.count, all == nil,
                (long)self.applicationState]);
    }
    [super sendEvent:event];
}
@end

@interface TPWindow : UIWindow
@end
@implementation TPWindow
- (void)sendEvent:(UIEvent *)event {
    if (event.type == UIEventTypeTouches) {
        NSSet<UITouch *> *local = [event touchesForWindow:self];
        record([NSString stringWithFormat:@"window seq=%lu eventTime=%.6f all=%lu local=%lu localNil=%d key=%d scene=%ld bounds=%@",
                eventNumber, event.timestamp, (unsigned long)event.allTouches.count,
                (unsigned long)local.count, local == nil, self.isKeyWindow,
                (long)self.windowScene.activationState, NSStringFromCGRect(self.bounds)]);
        for (UITouch *t in local) {
            record([NSString stringWithFormat:@"touch seq=%lu id=%p time=%.6f phase=%ld xy=%@ view=%@",
                    eventNumber, (__bridge void *)t, t.timestamp, (long)t.phase,
                    NSStringFromCGPoint([t locationInView:self]), labelFor(t.view)]);
        }
    }
    [super sendEvent:event];
}
@end

@interface TPPage : UIViewController
@property(nonatomic,strong) UILabel *status;
@property(nonatomic) NSUInteger clicks;
@property(nonatomic) NSUInteger edges;
@end
@implementation TPPage
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.whiteColor;
    self.view.accessibilityIdentifier = @"surface";
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    [button setTitle:@"Tap here" forState:UIControlStateNormal];
    button.accessibilityIdentifier = @"centerButton";
    [button addTarget:self action:@selector(tapped:) forControlEvents:UIControlEventTouchUpInside];
    self.status = [[UILabel alloc] init];
    self.status.textColor = UIColor.blackColor;
    self.status.textAlignment = NSTextAlignmentCenter;
    self.status.text = @"TouchProbe | taps 0 | edges 0";
    for (UIView *v in @[button, self.status]) {
        v.translatesAutoresizingMaskIntoConstraints = NO;
        [self.view addSubview:v];
    }
    [NSLayoutConstraint activateConstraints:@[
        [button.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [button.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [button.widthAnchor constraintEqualToConstant:160],
        [button.heightAnchor constraintEqualToConstant:64],
        [self.status.centerXAnchor constraintEqualToAnchor:button.centerXAnchor],
        [self.status.bottomAnchor constraintEqualToAnchor:button.topAnchor constant:-16]
    ]];
    UIScreenEdgePanGestureRecognizer *edge = [[UIScreenEdgePanGestureRecognizer alloc]
        initWithTarget:self action:@selector(swiped:)];
    edge.edges = UIRectEdgeBottom;
    [self.view addGestureRecognizer:edge];
}
- (void)refresh {
    self.status.text = [NSString stringWithFormat:@"TouchProbe | taps %lu | edges %lu",
                        (unsigned long)self.clicks, (unsigned long)self.edges];
}
- (void)tapped:(UIButton *)sender {
    self.clicks += 1;
    record([NSString stringWithFormat:@"button count=%lu", (unsigned long)self.clicks]);
    [self refresh];
}
- (void)swiped:(UIScreenEdgePanGestureRecognizer *)edge {
    record([NSString stringWithFormat:@"edge state=%ld xy=%@ translation=%@",
            (long)edge.state, NSStringFromCGPoint([edge locationInView:self.view]),
            NSStringFromCGPoint([edge translationInView:self.view])]);
    if (edge.state == UIGestureRecognizerStateEnded) { self.edges += 1; [self refresh]; }
}
@end

@interface TPScene : UIResponder <UIWindowSceneDelegate>
@property(nonatomic,strong) UIWindow *window;
@end
@implementation TPScene
- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session
      options:(UISceneConnectionOptions *)options {
    if (![scene isKindOfClass:UIWindowScene.class]) return;
    self.window = [[TPWindow alloc] initWithWindowScene:(UIWindowScene *)scene];
    self.window.rootViewController = [[TPPage alloc] init];
    [self.window makeKeyAndVisible];
    record([NSString stringWithFormat:@"connected session=%@ key=%d",session.persistentIdentifier,self.window.isKeyWindow]);
}
- (void)sceneDidBecomeActive:(UIScene *)scene { record([NSString stringWithFormat:@"active key=%d",self.window.isKeyWindow]); }
- (void)sceneWillResignActive:(UIScene *)scene { record(@"inactive"); }
- (void)sceneDidEnterBackground:(UIScene *)scene { record(@"background"); }
- (void)sceneDidDisconnect:(UIScene *)scene { record(@"disconnected"); }
@end

@interface TPDelegate : UIResponder <UIApplicationDelegate>
@end
@implementation TPDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    record(@"didFinishLaunching");
    return YES;
}
@end

int main(int argc, char **argv) {
    @autoreleasepool {
        NSURL *dir = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory
                                                          inDomains:NSUserDomainMask].firstObject;
        if (dir && [NSFileManager.defaultManager createDirectoryAtURL:dir withIntermediateDirectories:YES attributes:nil error:nullptr]) {
            NSString *name = [NSString stringWithFormat:@"TouchProbe-%@.log", NSUUID.UUID.UUIDString];
            NSURL *url = [dir URLByAppendingPathComponent:name];
            probeLog = fopen(url.fileSystemRepresentation, "w");
            if (probeLog) {
                setvbuf(probeLog, NULL, _IOLBF, 0);
                fprintf(stderr, "TouchProbe log %s\n", url.fileSystemRepresentation);
            }
        }
        record([NSString stringWithFormat:@"start pid=%d", getpid()]);
        return UIApplicationMain(argc, argv, NSStringFromClass(TPApplication.class), NSStringFromClass(TPDelegate.class));
    }
}
