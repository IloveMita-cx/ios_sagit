// SPDX-License-Identifier: BSD-2-Clause
// Registry diagnostics and explicitly requested synthetic input diagnostics.
#import <Foundation/Foundation.h>
#include <IOKitUser.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <signal.h>
#include <unistd.h>
#include <mach/mach_time.h>
#include <math.h>

// Apple IOHIDEventSystemMonitor and HIDEventSystemClient.h define this
// monitor-only SPI. Event descriptions avoid private event-structure layouts.
extern "C" {
typedef const void *InputEventClient;
typedef const void *InputEvent;
InputEventClient IOHIDEventSystemClientCreateWithType(CFAllocatorRef,int,CFDictionaryRef);
void IOHIDEventSystemClientRegisterEventCallback(InputEventClient,void (*)(void *,void *,void *,InputEvent),void *,void *);
void IOHIDEventSystemClientScheduleWithRunLoop(InputEventClient,CFRunLoopRef,CFStringRef);
void IOHIDEventSystemClientSetMatching(InputEventClient,CFDictionaryRef);
void IOHIDEventSystemClientUnscheduleWithRunLoop(InputEventClient,CFRunLoopRef,CFStringRef);
CFArrayRef IOHIDEventSystemClientCopyServices(InputEventClient);
CFTypeRef IOHIDEventSystemClientCopyProperty(InputEventClient,CFStringRef);
CFTypeRef IOHIDServiceClientCopyProperty(const void *,CFStringRef);
CFTypeRef IOHIDServiceClientGetRegistryID(const void *);
uint32_t IOHIDEventGetType(InputEvent);
uint64_t IOHIDEventGetSenderID(InputEvent);
uint64_t IOHIDEventGetTimeStamp(InputEvent);
int64_t IOHIDEventGetIntegerValue(InputEvent,uint32_t);
double IOHIDEventGetFloatValue(InputEvent,uint32_t);
CFArrayRef IOHIDEventGetChildren(InputEvent);
// ABI from Apple's WebKit PAL IOKitSPIIOS.h; the SDK exports these symbols.
InputEvent IOHIDEventCreateDigitizerEvent(CFAllocatorRef,uint64_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,double,double,double,double,double,boolean_t,boolean_t,uint32_t);
InputEvent IOHIDEventCreateDigitizerFingerEvent(CFAllocatorRef,uint64_t,uint32_t,uint32_t,uint32_t,double,double,double,double,double,boolean_t,boolean_t,uint32_t);
void IOHIDEventSetIntegerValue(InputEvent,uint32_t,CFIndex);
void IOHIDEventSetFloatValue(InputEvent,uint32_t,double);
void IOHIDEventSetSenderID(InputEvent,uint64_t);
void IOHIDEventAppendEvent(InputEvent,InputEvent,uint32_t);
void IOHIDEventSystemClientDispatchEvent(InputEventClient,InputEvent);
}
static unsigned eventCount=0,digitizerCount=0;
static bool compactEvents=false;
static void receiveEvent(void *,void *,void *,InputEvent event) {
    ++eventCount;
    const auto type=IOHIDEventGetType(event);
    if(type!=11) return;
    ++digitizerCount;
    if (digitizerCount == 1) {
        printf("INPUT_FIELDS");
        for (int fi = 720896; fi <= 720928; ++fi) printf(" %d=%lld", fi, (long long)IOHIDEventGetIntegerValue(event, fi));
        auto kids0 = IOHIDEventGetChildren(event);
        if (kids0 && CFArrayGetCount(kids0)) {
            auto kid = (InputEvent)CFArrayGetValueAtIndex(kids0, 0);
            printf(" | KID");
            for (int fi = 720896; fi <= 720928; ++fi) printf(" %d=%lld", fi, (long long)IOHIDEventGetIntegerValue(kid, fi));
        }
        printf("\n");
        fflush(stdout);
    }
    if(compactEvents && digitizerCount>96 && digitizerCount%128!=0)return;
    if(compactEvents) {
        printf("INPUT_FRAME n=%u timestamp=%llu now=%llu sender=%llu mask=%lld range=%lld touch=%lld x=%.6f y=%.6f",
            digitizerCount,(unsigned long long)IOHIDEventGetTimeStamp(event),(unsigned long long)mach_absolute_time(),
            (unsigned long long)IOHIDEventGetSenderID(event),
            (long long)IOHIDEventGetIntegerValue(event,720903),(long long)IOHIDEventGetIntegerValue(event,720904),
            (long long)IOHIDEventGetIntegerValue(event,720905),IOHIDEventGetFloatValue(event,720896),IOHIDEventGetFloatValue(event,720897));
        auto children=IOHIDEventGetChildren(event);
        for(CFIndex i=0;children && i<CFArrayGetCount(children);++i) {
            auto child=CFArrayGetValueAtIndex(children,i);
            if(IOHIDEventGetType(child)!=11)continue;
            printf(" child=%lld,%lld,%lld,%.6f,%.6f",(long long)IOHIDEventGetIntegerValue(child,720901),
                (long long)IOHIDEventGetIntegerValue(child,720903),(long long)IOHIDEventGetIntegerValue(child,720905),
                IOHIDEventGetFloatValue(child,720896),IOHIDEventGetFloatValue(child,720897));
        }
        putchar('\n');fflush(stdout);return;
    }
    // Bound the capture volume, retaining the complete native descriptions.
    if(digitizerCount>400) return;
    CFStringRef description=CFCopyDescription(event);
    printf("INPUT_EVENT n=%u sender=%llu type=%u %s\n",digitizerCount,
        (unsigned long long)IOHIDEventGetSenderID(event),type,
        description ? [(__bridge NSString *)description UTF8String] : "<no description>");
    if(description)CFRelease(description);
    fflush(stdout);
}
static int systemState() {
    alarm(15);
    auto client=IOHIDEventSystemClientCreateWithType(kCFAllocatorDefault,0,nullptr);
    if(!client){puts("INPUT_SYSTEM admin_client_unavailable");return 1;}
    for(NSString *key in @[@"HIDDebug",@"ClientRecords",@"ServiceRecords",@"SessionFilterDebug",@"ActivityState"]) {
        auto value=IOHIDEventSystemClientCopyProperty(client,(__bridge CFStringRef)key);
        printf("INPUT_SYSTEM_PROPERTY key=%s value=%s\n",key.UTF8String,value?[(__bridge id)value description].UTF8String:"<unavailable>");
        if(value)CFRelease(value);
    }
    auto services=IOHIDEventSystemClientCopyServices(client);
    for(CFIndex i=0;services && i<CFArrayGetCount(services);++i) {
        auto service=CFArrayGetValueAtIndex(services,i);
        auto product=IOHIDServiceClientCopyProperty(service,CFSTR("Product"));
        if(product && CFGetTypeID(product)==CFStringGetTypeID() && CFEqual(product,CFSTR("Mi 6 Touchscreen"))) {
            for(NSString *key in @[@"ServiceFilterDebug",@"ServicePluginDebug",@"HIDDebug",@"DisplayUUID",@"DigitizerCollectionDispatch"]) {
                auto value=IOHIDServiceClientCopyProperty(service,(__bridge CFStringRef)key);
                printf("INPUT_TOUCH_PROPERTY key=%s value=%s\n",key.UTF8String,value?[(__bridge id)value description].UTF8String:"<unavailable>");
                if(value)CFRelease(value);
            }
        }
        if(product)CFRelease(product);
    }
    if(services)CFRelease(services);CFRelease(client);alarm(0);return 0;
}
static int deliveryState() {
    alarm(15);
    void *library=dlopen("/System/Library/PrivateFrameworks/BackBoardServices.framework/BackBoardServices",RTLD_LAZY);
    Class cls=NSClassFromString(@"BKSHIDEventDeliveryManager");
    SEL shared=sel_registerName("sharedInstance"),graph=sel_registerName("deliveryGraphDescription");
    Method factory=class_getClassMethod(cls,shared),query=class_getInstanceMethod(cls,graph);
    if(!library || !factory || !query || strcmp(method_getTypeEncoding(factory),"@16@0:8") ||
        strcmp(method_getTypeEncoding(query),"@16@0:8")) {puts("INPUT_DELIVERY native_ABI_unavailable");return 1;}
    auto send=reinterpret_cast<id (*)(id,SEL)>(objc_msgSend);
    @try {
        id manager=send(cls,shared);
        id value=send(manager,graph);
        printf("INPUT_DELIVERY_GRAPH %s\n",value?[[value description] UTF8String]:"<unavailable>");
        alarm(0);return value?0:1;
    } @catch(NSException *error) {
        printf("INPUT_DELIVERY_ERROR %s\n",error.reason.UTF8String);alarm(0);return 1;
    }
}
static int homeButtonType() {
    alarm(15);
    typedef long(*EffectiveHomeButtonTypeFn)(void);
    const char *paths[]={
        "/System/Library/PrivateFrameworks/SpringBoardFoundation.framework/SpringBoardFoundation",
        "/System/Library/PrivateFrameworks/FrontBoard.framework/FrontBoard"};
    for(const char *p:paths){
        void *lib=dlopen(p,RTLD_LAZY);
        if(!lib)continue;
        auto fn=(EffectiveHomeButtonTypeFn)dlsym(lib,"SBFEffectiveHomeButtonType");
        if(!fn)continue;
        long value=fn();
        printf("HOME_BUTTON_TYPE value=%ld framework=%s\n",value,p);
        alarm(0);return 0;
    }
    puts("HOME_BUTTON_TYPE symbol_unavailable");
    alarm(0);return 1;
}
static int tap(double x,double y) {
    if(geteuid() || !isfinite(x) || !isfinite(y) || x<0 || x>1 || y<0 || y>1)return 2;
    alarm(15);
    auto client=IOHIDEventSystemClientCreateWithType(kCFAllocatorDefault,0,nullptr);
    if(!client){puts("INPUT_TAP admin_client_unavailable");return 1;}
    uint64_t sender=0;unsigned matches=0;
    auto services=IOHIDEventSystemClientCopyServices(client);
    for(CFIndex i=0;services && i<CFArrayGetCount(services);++i) {
        auto service=CFArrayGetValueAtIndex(services,i);
        auto product=IOHIDServiceClientCopyProperty(service,CFSTR("Product"));
        if(product && CFGetTypeID(product)==CFStringGetTypeID() && CFEqual(product,CFSTR("Mi 6 Touchscreen"))) {
            auto registryID=IOHIDServiceClientGetRegistryID(service);
            if(registryID && CFGetTypeID(registryID)==CFNumberGetTypeID() &&
                CFNumberGetValue((CFNumberRef)registryID,kCFNumberSInt64Type,&sender))++matches;
        }
        if(product)CFRelease(product);
    }
    if(services)CFRelease(services);
    if(matches!=1 || !sender){puts("INPUT_TAP unique_touch_service_unavailable");CFRelease(client);return 1;}
    compactEvents=true;
    IOHIDEventSystemClientRegisterEventCallback(client,receiveEvent,nullptr,nullptr);
    IOHIDEventSystemClientScheduleWithRunLoop(client,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);
    printf("INPUT_TAP begin physical_input=0 sender=%llu normalized_x=%.6f normalized_y=%.6f\n",(unsigned long long)sender,x,y);
    bool ok=true;
    for(unsigned phase=0;phase<2;++phase) {
        const bool down=phase==0;const auto timestamp=mach_absolute_time();
        // Match the physical collection's absolute, collection and built-in
        // option bits (0x13), while keeping this operation visibly synthetic.
        auto hand=IOHIDEventCreateDigitizerEvent(kCFAllocatorDefault,timestamp,3,0,2,down?7:3,down?1:0,x,y,0,0,0,down,down,0x13);
        auto finger=IOHIDEventCreateDigitizerFingerEvent(kCFAllocatorDefault,timestamp,0,2,down?7:3,x,y,0,down?0.5:0,0,down,down,1);
        if(!hand || !finger) {if(hand)CFRelease(hand);if(finger)CFRelease(finger);ok=false;break;}
        IOHIDEventSetIntegerValue(hand,720921,1); // DigitizerIsDisplayIntegrated
        IOHIDEventSetFloatValue(finger,720916,5); // MajorRadius
        IOHIDEventSetFloatValue(finger,720917,5); // MinorRadius
        IOHIDEventAppendEvent(hand,finger,0);IOHIDEventSetSenderID(hand,sender);
        IOHIDEventSystemClientDispatchEvent(client,hand);
        printf("INPUT_TAP phase=%s timestamp=%llu physical_input=0 dispatch_returned=1 ui_response_verified=0\n",down?"down":"up",(unsigned long long)timestamp);
        CFRelease(finger);CFRelease(hand);
        CFRunLoopRunInMode(kCFRunLoopDefaultMode,down?0.12:1.0,false);
    }
    IOHIDEventSystemClientUnscheduleWithRunLoop(client,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);
    CFRelease(client);alarm(0);printf("INPUT_TAP end constructed=%u observed_digitizers=%u\n",ok,digitizerCount);return ok?0:1;
}
static int hidTap(double x,double y,unsigned pressure) {
    if (geteuid() || !isfinite(x) || !isfinite(y) || x<0 || x>1 || y<0 || y>1 || pressure>255) return 2;
    alarm(15);
    mach_port_t iterator=0;
    auto status=IOServiceGetMatchingServices(0,IOServiceMatching("SynapticsTouch"),&iterator);
    if (status) return 1;
    auto service=IOIteratorNext(iterator),extra=IOIteratorNext(iterator);IOObjectRelease(iterator);
    if (!service || extra) { if(service)IOObjectRelease(service);if(extra)IOObjectRelease(extra);return 1; }
    auto client=IOHIDEventSystemClientCreateWithType(kCFAllocatorDefault,1,nullptr);
    if (!client) { IOObjectRelease(service);return 1; }
    IOHIDEventSystemClientRegisterEventCallback(client,receiveEvent,nullptr,nullptr);
    IOHIDEventSystemClientScheduleWithRunLoop(client,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);
    const unsigned nx=unsigned(lround(x*32767)),ny=unsigned(lround(y*32767));
    const uint8_t request[]={uint8_t(nx),uint8_t(nx>>8),uint8_t(ny),uint8_t(ny>>8),uint8_t(pressure),8,8};
    NSData *data=[NSData dataWithBytes:request length:sizeof(request)];
    status=IORegistryEntrySetCFProperties(service,(__bridge CFTypeRef)@{@"TouchDiagnosticTap":data});
    printf("INPUT_HID_TAP physical_input=0 driver_report=1 native_parser=1 x=%.6f y=%.6f pressure=%u status=0x%x\n",x,y,pressure,status);
    fflush(stdout);
    CFRunLoopRunInMode(kCFRunLoopDefaultMode,1.5,false);
    auto released=IORegistryEntryCreateCFProperty(service,CFSTR("TouchDiagnosticLastReleased"),nullptr,0);
    const bool ok=!status && released==kCFBooleanTrue;
    printf("INPUT_HID_TAP_END released=%u observed_digitizers=%u ui_response_verified=0\n",ok,digitizerCount);
    if(released)CFRelease(released);
    IOHIDEventSystemClientUnscheduleWithRunLoop(client,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);
    CFRelease(client);IOObjectRelease(service);alarm(0);return ok?0:1;
}
static int monitor(unsigned seconds) {
    auto client=IOHIDEventSystemClientCreateWithType(kCFAllocatorDefault,1,nullptr);
    if(!client){fputs("INPUT_MONITOR create_failed\n",stderr);return 1;}
    IOHIDEventSystemClientRegisterEventCallback(client,receiveEvent,nullptr,nullptr);
    IOHIDEventSystemClientScheduleWithRunLoop(client,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);
    auto services=IOHIDEventSystemClientCopyServices(client);
    const CFIndex count=services ? CFArrayGetCount(services) : 0;
    printf("INPUT_MONITOR ready seconds=%u services=%ld\n",seconds,(long)count);
    NSArray *keys=@[@"Product",@"Transport",@"Built-In",@"PrimaryUsagePage",@"PrimaryUsage",
        @"DeviceUsagePairs",@"DisplayIntegrated",@"DigitizerCollectionDispatch",@"DisplayUUID",@"HIDServiceSupport"];
    for(CFIndex i=0;i<count;++i){
        auto service=CFArrayGetValueAtIndex(services,i);
        printf("INPUT_USER_SERVICE id=%s\n",[(__bridge id)IOHIDServiceClientGetRegistryID(service) description].UTF8String);
        for(NSString *key in keys){
            auto value=IOHIDServiceClientCopyProperty(service,(__bridge CFStringRef)key);
            if(value){printf("  %s=%s\n",key.UTF8String,[(__bridge id)value description].UTF8String);CFRelease(value);}
        }
    }
    if(services)CFRelease(services);
    fflush(stdout);
    const auto until=CFAbsoluteTimeGetCurrent()+seconds;
    while(CFAbsoluteTimeGetCurrent()<until)CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.25,false);
    IOHIDEventSystemClientUnscheduleWithRunLoop(client,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);
    CFRelease(client);
    printf("INPUT_MONITOR done events=%u digitizers=%u\n",eventCount,digitizerCount);
    return 0;
}
// Resolve the native settings object's actual Objective-C signatures before
// invoking it. Unsupported firmware reports failure rather than writing a
// guessed preference key. Run this command in the mobile user's context.
static int enableAssistiveTouch() {
    alarm(20);
    setenv("HOME","/var/mobile",1);
    setenv("CFFIXED_USER_HOME","/var/mobile",1);
    setenv("USER","mobile",1);setenv("LOGNAME","mobile",1);
    if(geteuid()==0 && (setgid(501) || setuid(501))) {
        perror("ACCESSIBILITY mobile credentials");return 1;
    }
    if(geteuid()!=501){puts("ACCESSIBILITY wrong_user");return 1;}
    dlopen("/System/Library/PrivateFrameworks/AccessibilityUtilities.framework/AccessibilityUtilities",RTLD_NOW);
    Class cls=NSClassFromString(@"AXSettings");
    SEL shared=NSSelectorFromString(@"sharedInstance");
    if(!cls || ![cls respondsToSelector:shared]){puts("ACCESSIBILITY settings_unavailable");return 1;}
    NSMethodSignature *factory=[cls methodSignatureForSelector:shared];
    if(!factory || factory.numberOfArguments!=2 || strcmp(factory.methodReturnType,"@"))return 1;
    NSInvocation *make=[NSInvocation invocationWithMethodSignature:factory];
    make.target=cls;make.selector=shared;[make invoke];
    __unsafe_unretained id settings=nil;[make getReturnValue:&settings];
    SEL get=NSSelectorFromString(@"assistiveTouchEnabled"),set=NSSelectorFromString(@"setAssistiveTouchEnabled:");
    NSMethodSignature *gs=[settings methodSignatureForSelector:get],*ss=[settings methodSignatureForSelector:set];
    if(!gs || !ss || gs.numberOfArguments!=2 || ss.numberOfArguments!=3 ||
       (strcmp(gs.methodReturnType,"B") && strcmp(gs.methodReturnType,"c")) ||
       strcmp(ss.methodReturnType,"v") ||
       (strcmp([ss getArgumentTypeAtIndex:2],"B") && strcmp([ss getArgumentTypeAtIndex:2],"c"))) {
        puts("ACCESSIBILITY unsupported_settings_ABI");return 1;
    }
    NSInvocation *read=[NSInvocation invocationWithMethodSignature:gs];
    read.target=settings;read.selector=get;[read invoke];
    unsigned char before=0,after=0;[read getReturnValue:&before];
    NSInvocation *write=[NSInvocation invocationWithMethodSignature:ss];
    write.target=settings;write.selector=set;unsigned char enabled=1;
    [write setArgument:&enabled atIndex:2];[write invoke];
    // Allow the native asynchronous preference write and notification to run.
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:3.0]];
    printf("ACCESSIBILITY uid=%u home=%s sync=%u\n",getuid(),getenv("HOME"),
           CFPreferencesAppSynchronize(CFSTR("com.apple.Accessibility")));
    [read invoke];[read getReturnValue:&after];
    printf("ACCESSIBILITY assistive_touch_before=%u after=%u ui_visibility=unverified\n",before,after);
    return after?0:1;
}
static NSString *svcProp(mach_port_t service, const char *key) {
    auto v = IORegistryEntryCreateCFProperty(service, (__bridge CFStringRef)[NSString stringWithUTF8String:key], kCFAllocatorDefault, 0);
    if (!v) return @"-";
    NSString *s = [(__bridge id)v description];
    CFRelease(v);
    return s;
}
static int rawSample(unsigned seconds) {
    if (geteuid()) return 2;
    alarm((unsigned)(seconds + 10));
    mach_port_t iterator=0;
    if (IOServiceGetMatchingServices(0,IOServiceMatching("SynapticsTouch"),&iterator)) return 1;
    auto service=IOIteratorNext(iterator);IOObjectRelease(iterator);
    if (!service) return 1;
    printf("INPUT_RAWSAMPLE ready seconds=%u\n",seconds);
    fflush(stdout);
    const auto until=CFAbsoluteTimeGetCurrent()+seconds;
    unsigned n=0;
    while (CFAbsoluteTimeGetCurrent()<until) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.05,false);
        ++n;
        printf("INPUT_RAWSAMPLE n=%u contacts=%s down=%s up=%s raw=%s status=%s\n",
            n, svcProp(service,"TouchContacts").UTF8String, svcProp(service,"TouchDownTransitions").UTF8String,
            svcProp(service,"TouchUpTransitions").UTF8String, svcProp(service,"RMILastRawFrame").UTF8String,
            svcProp(service,"RMILastStatus").UTF8String);
        fflush(stdout);
    }
    IOObjectRelease(service);
    alarm(0);
    return 0;
}
static int clientMatch(unsigned seconds) {
    if (geteuid()) return 2;
    alarm((unsigned)(seconds + 10));
    auto client = IOHIDEventSystemClientCreateWithType(kCFAllocatorDefault, 0, nullptr);
    if (!client) { puts("INPUT_MATCH no_client"); return 1; }
    CFMutableDictionaryRef m = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int page = 13, usage = 4;
    CFNumberRef np = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &page);
    CFNumberRef nu = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &usage);
    CFDictionarySetValue(m, CFSTR("PrimaryUsagePage"), np);
    CFDictionarySetValue(m, CFSTR("PrimaryUsage"), nu);
    IOHIDEventSystemClientSetMatching(client, m);
    CFRelease(np); CFRelease(nu); CFRelease(m);
    IOHIDEventSystemClientRegisterEventCallback(client, receiveEvent, nullptr, nullptr);
    IOHIDEventSystemClientScheduleWithRunLoop(client, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    auto services = IOHIDEventSystemClientCopyServices(client);
    printf("INPUT_MATCH ready seconds=%u matched_services=%ld\n", seconds, services ? (long)CFArrayGetCount(services) : -1L);
    if (services) CFRelease(services);
    fflush(stdout);
    const auto until = CFAbsoluteTimeGetCurrent() + seconds;
    while (CFAbsoluteTimeGetCurrent() < until) CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, false);
    IOHIDEventSystemClientUnscheduleWithRunLoop(client, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    printf("INPUT_MATCH done events=%u digitizers=%u\n", eventCount, digitizerCount);
    CFRelease(client);
    alarm(0);
    return 0;
}
static int makeDir(const char *path) {
    if (geteuid()) return 2;
    char buf[1024];
    snprintf(buf, sizeof buf, "%s", path);
    for (char *p = buf + 1; *p; ++p) {
        if (*p == '/') { *p = 0; mkdir(buf, 0755); *p = '/'; }
    }
    if (mkdir(buf, 0755) && errno != EEXIST) { perror("mkdir"); return 1; }
    return 0;
}
static int copyFile(const char *src, const char *dst) {
    if (geteuid()) return 2;
    int in = open(src, O_RDONLY);
    if (in < 0) { perror("open"); return 1; }
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out < 0) { perror("create"); close(in); return 1; }
    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0) {
        if (write(out, buf, n) != n) { perror("write"); close(in); close(out); return 1; }
    }
    close(in);
    close(out);
    chmod(dst, 0755);
    return 0;
}
int main(int argc,const char *argv[]) {
    @autoreleasepool {
        if(argc==2 && !strcmp(argv[1],"enable-assistive-touch"))return enableAssistiveTouch();
        if(argc==2 && !strcmp(argv[1],"system"))return systemState();
        if(argc==2 && !strcmp(argv[1],"delivery"))return deliveryState();
        if(argc==2 && !strcmp(argv[1],"homebutton"))return homeButtonType();
        if(argc==2 && !strcmp(argv[1],"client-match")) return clientMatch(12);
        if(argc==3 && !strcmp(argv[1],"mkdir")) return makeDir(argv[2]);
        if(argc==4 && !strcmp(argv[1],"cp")) return copyFile(argv[2],argv[3]);
        if(argc==3 && !strcmp(argv[1],"raw-sample")) { char *e=nullptr; const auto s=strtoul(argv[2],&e,10); if(!*argv[2] || *e || !s || s>60) return 2; return rawSample((unsigned)s); }
        if(argc==4 && !strcmp(argv[1],"tap")) {
            char *xEnd=nullptr,*yEnd=nullptr;const auto x=strtod(argv[2],&xEnd),y=strtod(argv[3],&yEnd);
            if(!*argv[2] || !*argv[3] || *xEnd || *yEnd)return 2;
            return tap(x,y);
        }
        if((argc==4 || argc==5) && !strcmp(argv[1],"hid-tap")) {
            char *xe=nullptr,*ye=nullptr,*pe=nullptr;
            const auto x=strtod(argv[2],&xe),y=strtod(argv[3],&ye);
            const auto pressure=argc==5?strtoul(argv[4],&pe,10):65;
            if(!*argv[2] || !*argv[3] || *xe || *ye || pressure>255 || (argc==5 && (!*argv[4] || *pe)))return 2;
            return hidTap(x,y,unsigned(pressure));
        }
        if((argc==3 || (argc==4 && !strcmp(argv[3],"--compact"))) && !strcmp(argv[1],"monitor")){
            char *end=nullptr;const auto seconds=strtoul(argv[2],&end,10);
            if(!*argv[2] || *end || !seconds || seconds>300)return 2;
            compactEvents=argc==4;return monitor(unsigned(seconds));
        }
        const bool elements=argc==3 && !strcmp(argv[2],"--elements");
        if((argc!=2 && !elements) || strcmp(argv[1],"registry")) {
            fputs("usage: inputctl registry [--elements] | system | delivery | tap NORMALIZED_X NORMALIZED_Y | hid-tap SENSOR_X SENSOR_Y [PRESSURE] | monitor SECONDS [--compact] (1..300)\n",stderr);return 2;
        }
        int cpus=0;size_t cpuBytes=sizeof(cpus);
        if(!sysctlbyname("hw.ncpu",&cpus,&cpuBytes,nullptr,0))printf("INPUT_RUNTIME cpus=%d uptime=%.3f\n",cpus,NSProcessInfo.processInfo.systemUptime);
        const char *classes[]={"QcomSCM","QcomGPIO","QcomI2C","GenericI2CDevice","SynapticsTouch","FingerprintHID","QcomButtons","IOHIDInterface","IOHIDEventDriver","IOHIDEventServiceUserClient"};
        NSArray *keys=@[@"IOClass",@"CFBundleIdentifier",@"CFBundleVersion",@"Product",@"Transport",@"PrimaryUsagePage",@"PrimaryUsage",
            @"I2CBusFrequency",@"I2CRetainedResources",@"RMIProductID",@"RMIFunction",@"RMIMaxContacts",@"RMILastError",@"RMIRecoveryAttempts",
            @"TouchInputReports",@"TouchContacts",@"HIDInputOffline",@"HomeSecureWorker",@"HomeInputReports",@"HomeSensorSamples",@"HomeLastDown",
            @"HomeTraceEnabled",@"HomeLastSecureUS",@"HomeMaxSecureUS",@"HomeIRQRequests",@"HomeTimerRequests",@"HomeIRQLevel",
            @"HIDDiagnosticInputEnabled",@"HIDDiagnosticPulses",@"HIDDiagnosticLastReleased",@"ButtonInputReports",
            @"FingerprintSecureSessionQuarantined",@"HIDInputReportBytes",@"DisplayIntegrated",@"DigitizerCollectionDispatch",
            @"Built-In",@"DeviceUsagePairs",@"HIDServiceSupport",@"IOUserClientClass",@"IOCFPlugInTypes",@"DisplayUUID",
            @"TouchActiveFrames",@"TouchDownTransitions",@"TouchUpTransitions",@"TouchLastActiveHID",@"TouchLastActiveRMI",
            @"TouchDiagnosticPulses",@"TouchDiagnosticReports",@"TouchDiagnosticLastReleased",
            @"RMIMaxX",@"RMIMaxY",@"RMIDataAddress",@"RMILastRawFrame",@"RMILastStatus"];
        for(const char *name:classes) {
            mach_port_t iterator=0;unsigned count=0;
            auto result=IOServiceGetMatchingServices(0,IOServiceMatching(name),&iterator);
            if(result) {printf("INPUT_MATCH class=%s error=0x%x\n",name,result);continue;}
            for(mach_port_t service;(service=IOIteratorNext(iterator));) {
                ++count;uint64_t identifier=0;IORegistryEntryGetRegistryEntryID(service,&identifier);
                printf("INPUT_SERVICE class=%s id=%llu\n",name,identifier);
                for(NSString *key in keys) {
                    CFTypeRef value=IORegistryEntryCreateCFProperty(service,(__bridge CFStringRef)key,nullptr,0);
                    if(value) {printf("  %s=%s\n",key.UTF8String,[(__bridge id)value description].UTF8String);CFRelease(value);}
                }
                // A full ten-contact element tree can occupy the UART for
                // minutes. Keep routine captures bounded; request it explicitly.
                if(elements) {
                    CFTypeRef value=IORegistryEntryCreateCFProperty(service,CFSTR("Digitizer"),nullptr,0);
                    if(value) {printf("  Digitizer=%s\n",[(__bridge id)value description].UTF8String);CFRelease(value);}
                }
                IOObjectRelease(service);
            }
            IOObjectRelease(iterator);printf("INPUT_COUNT class=%s count=%u\n",name,count);
        }
        return 0;
    }
}
