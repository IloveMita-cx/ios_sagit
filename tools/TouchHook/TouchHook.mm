// TouchHook: injected into UIKit apps to record the real UITouch objects.
// Loaded via DYLD_INSERT_LIBRARIES from FrontBoard's launchd environment.
#import <UIKit/UIKit.h>
#include <stdio.h>
#include <unistd.h>
#include <objc/runtime.h>

static FILE *gLog;
static unsigned long gAppEvents, gWindowEvents, gGestureChanges;
static unsigned long gMaxDetail = 400;

static void rec(NSString *line) {
    fprintf(gLog ?: stderr, "%s\n", line.UTF8String);
    fflush(gLog ?: stderr);
}

static NSString *viewLabel(UIView *v) {
    if (!v) return @"nil";
    return [NSString stringWithFormat:@"%@#%@", NSStringFromClass(v.class),
            v.accessibilityIdentifier ?: @"-"];
}

static NSString *touchLine(UIWindow *w, UITouch *t) {
    CGPoint p = [t locationInView:w];
    UIView *hit = [w hitTest:p withEvent:nil];
    return [NSString stringWithFormat:@"  touch %p phase=%ld ts=%.3f at=(%.1f,%.1f) view=%@ hit=%@",
            (__bridge void *)t, (long)t.phase, t.timestamp, p.x, p.y,
            viewLabel(t.view), viewLabel(hit)];
}

static void dumpEvent(const char *where, UIWindow *w, UIEvent *event) {
    if (event.type != UIEventTypeTouches) return;
    NSSet<UITouch *> *all = event.allTouches;
    NSSet<UITouch *> *local = w ? [event touchesForWindow:w] : nil;
    if (gWindowEvents < gMaxDetail) {
        rec([NSString stringWithFormat:
             @"%s seq=%lu all=%lu local=%lu nil=%d key=%d bounds=%@ sceneState=%ld",
             where, gWindowEvents, (unsigned long)all.count, (unsigned long)local.count,
             all == nil, w.isKeyWindow, w ? NSStringFromCGRect(w.bounds) : @"-",
             (long)w.windowScene.activationState]);
        for (UITouch *t in local) rec(touchLine(w, t));
    }
    ++gWindowEvents;
}

@interface UIWindow (TouchHook)
- (void)th_sendEvent:(UIEvent *)event;
@end

@implementation UIWindow (TouchHook)
- (void)th_sendEvent:(UIEvent *)event {
    dumpEvent("window", self, event);
    [self th_sendEvent:event];
}
@end

@interface UIApplication (TouchHook)
- (void)th_appSendEvent:(UIEvent *)event;
@end

@implementation UIApplication (TouchHook)
- (void)th_appSendEvent:(UIEvent *)event {
    if (event.type == UIEventTypeTouches) {
        if (gAppEvents < gMaxDetail) {
            rec([NSString stringWithFormat:@"app seq=%lu all=%lu nil=%d state=%ld",
                 gAppEvents, (unsigned long)event.allTouches.count,
                 event.allTouches == nil, (long)self.applicationState]);
        }
        ++gAppEvents;
    }
    [self th_appSendEvent:event];
}
@end

@interface UIGestureRecognizer (TouchHook)
- (void)th_setState:(long)state;
@end

@implementation UIGestureRecognizer (TouchHook)
- (void)th_setState:(long)state {
    if (gGestureChanges < gMaxDetail) {
        long old = (long)self.state;
        if (old != state) {
            rec([NSString stringWithFormat:@"gesture %@ %ld -> %ld",
                 NSStringFromClass(self.class), old, state]);
        }
        ++gGestureChanges;
    }
    [self th_setState:state];
}
@end

static void swizzle(const char *cls, const char *original, const char *replacement) {
    Method m = class_getInstanceMethod(objc_getClass(cls), sel_registerName(original));
    Method r = class_getInstanceMethod(objc_getClass(cls), sel_registerName(replacement));
    if (m && r) method_exchangeImplementations(m, r);
}

__attribute__((constructor)) static void install(void) {
    char path[256];
    snprintf(path, sizeof path, "/private/var/tmp/hook-%d.log", getpid());
    gLog = fopen(path, "a");
    NSString *bundle = [NSBundle mainBundle].bundleIdentifier ?: @"?";
    rec([NSString stringWithFormat:@"hook pid=%d bundle=%@", getpid(), bundle]);
    swizzle("UIWindow", "sendEvent:", "th_sendEvent:");
    swizzle("UIApplication", "sendEvent:", "th_appSendEvent:");
    swizzle("UIGestureRecognizer", "setState:", "th_setState:");
    rec(@"hook installed");
}
