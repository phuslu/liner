//go:build ingore
// Liner macOS status bar tray app
// Compile with: clang -x objective-c -fobjc-arc -mmacosx-version-min=11.0 -framework Cocoa -framework SystemConfiguration -framework Security liner.m -o liner-ui
#import <Cocoa/Cocoa.h>
#import <Security/Security.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <dispatch/dispatch.h>
#import <errno.h>
#import <fcntl.h>
#import <signal.h>
#import <stdio.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

static const NSUInteger ConsoleMaxLength = 2000000;
static const NSUInteger ConsoleTrimExtra = 100000;
static const NSTimeInterval ChildStopTimeout = 5.0;
static const CGFloat ConsoleBorderWidth = 3.0;

static int HasArgument(int argc, const char *argv[], const char *name) {
    for (int i = 1; i < argc; i++) {
        if (argv[i] && strcmp(argv[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int ShouldStayForeground(int argc, const char *argv[]) {
    return getenv("LINER_UI_FOREGROUND") || HasArgument(argc, argv, "--foreground") || HasArgument(argc, argv, "--no-detach");
}

static int IsTerminalLaunch(void) {
    if (isatty(STDIN_FILENO) || isatty(STDOUT_FILENO) || isatty(STDERR_FILENO)) {
        return 1;
    }

    int fd = open("/dev/tty", O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    close(fd);
    return 1;
}

static int RedirectStandardFilesToNull(void) {
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        return errno;
    }
    if (fd != STDIN_FILENO) {
        if (dup2(fd, STDIN_FILENO) < 0) {
            int err = errno;
            if (fd > STDERR_FILENO) {
                close(fd);
            }
            return err;
        }
    }
    if (fd != STDOUT_FILENO) {
        if (dup2(fd, STDOUT_FILENO) < 0) {
            int err = errno;
            if (fd > STDERR_FILENO) {
                close(fd);
            }
            return err;
        }
    }
    if (fd != STDERR_FILENO) {
        if (dup2(fd, STDERR_FILENO) < 0) {
            int err = errno;
            if (fd > STDERR_FILENO) {
                close(fd);
            }
            return err;
        }
    }
    if (fd > STDERR_FILENO) {
        close(fd);
    }
    return 0;
}

static void DetachFromTerminalIfNeeded(int argc, const char *argv[]) {
    if (!IsTerminalLaunch() || ShouldStayForeground(argc, argv)) {
        return;
    }

    int statusPipe[2];
    if (pipe(statusPipe) != 0) {
        fprintf(stderr, "liner-ui: pipe failed: %s\n", strerror(errno));
        return;
    }
    if (fcntl(statusPipe[1], F_SETFD, FD_CLOEXEC) < 0) {
        int err = errno;
        close(statusPipe[0]);
        close(statusPipe[1]);
        fprintf(stderr, "liner-ui: fcntl failed: %s\n", strerror(err));
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        int err = errno;
        close(statusPipe[0]);
        close(statusPipe[1]);
        fprintf(stderr, "liner-ui: fork failed: %s\n", strerror(err));
        return;
    }

    if (pid > 0) {
        close(statusPipe[1]);
        int childErr = 0;
        ssize_t n = 0;
        do {
            n = read(statusPipe[0], &childErr, sizeof(childErr));
        } while (n < 0 && errno == EINTR);
        close(statusPipe[0]);
        if (n > 0) {
            fprintf(stderr, "liner-ui: detach failed: %s\n", strerror(childErr));
            _exit(1);
        }
        if (n < 0) {
            fprintf(stderr, "liner-ui: detach status read failed: %s\n", strerror(errno));
            _exit(1);
        }
        fprintf(stderr, "liner-ui detached (pid %ld). Use --foreground to keep it attached.\n", (long)pid);
        _exit(0);
    }

    close(statusPipe[0]);
    if (setsid() < 0) {
        int err = errno;
        write(statusPipe[1], &err, sizeof(err));
        _exit(1);
    }
    int redirectErr = RedirectStandardFilesToNull();
    if (redirectErr != 0) {
        write(statusPipe[1], &redirectErr, sizeof(redirectErr));
        _exit(1);
    }
    execvp(argv[0], (char *const *)argv);

    int err = errno;
    write(statusPipe[1], &err, sizeof(err));
    _exit(127);
}

static NSColor *RGB(CGFloat red, CGFloat green, CGFloat blue) {
    return [NSColor colorWithDeviceRed:red green:green blue:blue alpha:1.0];
}

static NSString *Trim(NSString *value) {
    return [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

static NSString *TrimSpaces(NSString *value) {
    return [value stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
}

@interface ProxySettings : NSObject
@property(nonatomic, copy) NSString *host;
@property(nonatomic, copy) NSString *port;
@property(nonatomic, copy) NSString *pacURL;
+ (instancetype)settingsWithHost:(NSString *)host port:(NSString *)port;
+ (NSString *)urlHost:(NSString *)host;
- (NSString *)address;
@end

@implementation ProxySettings
+ (instancetype)settingsWithHost:(NSString *)host port:(NSString *)port {
    ProxySettings *settings = [ProxySettings new];
    settings.host = host;
    settings.port = port;
    return settings;
}

+ (NSString *)urlHost:(NSString *)host {
    if ([host containsString:@":"] && ![host hasPrefix:@"["] && ![host hasSuffix:@"]"]) {
        return [NSString stringWithFormat:@"[%@]", host];
    }
    return host;
}

- (NSString *)address {
    return [NSString stringWithFormat:@"%@:%@", [ProxySettings urlHost:self.host], self.port];
}
@end

@interface ChildCommand : NSObject
@property(nonatomic, copy) NSString *executable;
@property(nonatomic, copy) NSArray<NSString *> *arguments;
@property(nonatomic, copy) NSString *display;
+ (instancetype)commandWithExecutable:(NSString *)executable arguments:(NSArray<NSString *> *)arguments display:(NSString *)display;
@end

@implementation ChildCommand
+ (instancetype)commandWithExecutable:(NSString *)executable arguments:(NSArray<NSString *> *)arguments display:(NSString *)display {
    ChildCommand *command = [ChildCommand new];
    command.executable = executable;
    command.arguments = arguments ?: @[];
    command.display = display;
    return command;
}
@end

@interface ConsoleBorderView : NSView
@end

@implementation ConsoleBorderView
- (BOOL)isOpaque {
    return YES;
}

- (void)drawRect:(NSRect)dirtyRect {
    NSRect bounds = self.bounds;
    [[NSColor blackColor] setFill];
    NSRectFill(bounds);

    CGFloat borderWidth = MIN(ConsoleBorderWidth, MIN(bounds.size.width / 2.0, bounds.size.height / 2.0));
    if (borderWidth <= 0) {
        return;
    }

    [[NSColor separatorColor] setFill];
    NSRectFill(NSMakeRect(NSMinX(bounds), NSMinY(bounds), NSWidth(bounds), borderWidth));
    NSRectFill(NSMakeRect(NSMinX(bounds), NSMaxY(bounds) - borderWidth, NSWidth(bounds), borderWidth));
    NSRectFill(NSMakeRect(NSMinX(bounds), NSMinY(bounds), borderWidth, NSHeight(bounds)));
    NSRectFill(NSMakeRect(NSMaxX(bounds) - borderWidth, NSMinY(bounds), borderWidth, NSHeight(bounds)));
}
@end

@interface RuntimeError : NSException
+ (instancetype)errorWithReason:(NSString *)reason;
@end

@implementation RuntimeError
+ (instancetype)errorWithReason:(NSString *)reason {
    return (RuntimeError *)[RuntimeError exceptionWithName:@"RuntimeError" reason:reason userInfo:nil];
}
@end

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
@interface AppDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate, NSMenuDelegate, NSUserNotificationCenterDelegate>
#pragma clang diagnostic pop
@property(nonatomic, copy) NSString *childBin;
@property(nonatomic, copy) NSString *appTitle;
@property(nonatomic, copy) NSString *logWindowTitle;
@property(nonatomic, copy) NSString *workDir;
@property(nonatomic, strong) NSURL *workDirURL;
@property(nonatomic, strong) NSFont *consoleFont;
@property(nonatomic, strong) NSArray<NSColor *> *ansiColors;
@property(nonatomic, strong) NSColor *currentColor;
@property(nonatomic, strong) NSStatusItem *statusItem;
@property(nonatomic, strong) NSWindow *consoleWindow;
@property(nonatomic, strong) NSTextView *consoleView;
@property(nonatomic, strong) NSTask *childProcess;
@property(nonatomic) AuthorizationRef authorization;
@property(nonatomic, strong) NSMutableSet<NSNumber *> *expectedTerminationPIDs;
@property(nonatomic) BOOL terminatingFromSignal;
@property(nonatomic, strong) NSMutableArray *signalSources;
@property(nonatomic, strong) NSMenu *proxyMenu;
@property(nonatomic, strong) NSMenuItem *proxyDisableItem;
@property(nonatomic, strong) NSMenuItem *proxyPACItem;
@property(nonatomic, strong) NSMenuItem *proxyManualItem;
@property(nonatomic, strong) NSMenu *profileMenu;
@property(nonatomic, strong) NSMutableDictionary<NSString *, NSMenuItem *> *profileItems;
@property(nonatomic, strong) NSArray<NSString *> *profiles;
@property(nonatomic, copy) NSString *selectedProfile;
@property(nonatomic, strong) NSMenuItem *preferencesItem;
@property(nonatomic, strong) NSMenuItem *idleDisplaySleepItem;
@property(nonatomic, strong) NSMenuItem *startStopItem;
@property(nonatomic, strong) id idleDisplaySleepActivity;
@property(nonatomic, copy) NSString *sudoAskpassPath;
@end

@implementation AppDelegate
- (instancetype)init {
    self = [super init];
    if (!self) {
        return nil;
    }

    self.workDirURL = [self.class resolveWorkDirURL];
    self.workDir = self.workDirURL.path;
    self.childBin = @"liner";
    self.appTitle = [self.childBin capitalizedString];
    self.logWindowTitle = [NSString stringWithFormat:@"%@ Activity Log", self.appTitle];
    self.consoleFont = [NSFont fontWithName:@"Monaco" size:12.0] ?: [NSFont userFixedPitchFontOfSize:12.0];
    self.ansiColors = @[
        [NSColor whiteColor],
        RGB(0.7578, 0.2109, 0.1289),
        RGB(0.1445, 0.7344, 0.1406),
        RGB(0.6758, 0.6758, 0.1523),
        RGB(0.2852, 0.1797, 0.8789),
        RGB(0.8242, 0.2188, 0.8242),
        RGB(0.1992, 0.7305, 0.7813),
        RGB(0.7930, 0.7969, 0.8008),
    ];
    self.currentColor = self.ansiColors[0];
    self.expectedTerminationPIDs = [NSMutableSet set];
    self.signalSources = [NSMutableArray array];
    self.profileItems = [NSMutableDictionary dictionary];
    [self loadProfiles];
    return self;
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    [[NSFileManager defaultManager] changeCurrentDirectoryPath:self.workDir];
    [self setupNotifications];
    [self setupStatusItem];
    [self setupConsoleWindow];
    [self showStartupPrompt];
    [self showConsole:nil];
    [self installSignalHandlers];
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    [self stopChild];
    [self endIdleDisplaySleepActivity];
    [self cleanupSudoAskpass];
    if (self.authorization) {
        AuthorizationFree(self.authorization, kAuthorizationFlagDefaults);
        self.authorization = NULL;
    }
}

- (BOOL)windowShouldClose:(NSWindow *)sender {
    [sender orderOut:nil];
    return NO;
}

- (void)setupNotifications {
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdeprecated-declarations"
    [NSUserNotificationCenter defaultUserNotificationCenter].delegate = self;
    #pragma clang diagnostic pop
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
- (BOOL)userNotificationCenter:(NSUserNotificationCenter *)center shouldPresentNotification:(NSUserNotification *)notification {
    return YES;
}
#pragma clang diagnostic pop

+ (NSURL *)resolveWorkDirURL {
    NSBundle *bundle = [NSBundle mainBundle];
    if ([[bundle.bundlePath pathExtension] isEqualToString:@"app"] && bundle.resourcePath.length) {
        return [NSURL fileURLWithPath:bundle.resourcePath].standardizedURL;
    }

    NSString *raw = [NSProcessInfo processInfo].arguments.firstObject ?: @"./liner.m";
    NSString *path = raw;
    if (![path hasPrefix:@"/"]) {
        path = [[[NSFileManager defaultManager] currentDirectoryPath] stringByAppendingPathComponent:path];
    }
    path = [path stringByStandardizingPath].stringByResolvingSymlinksInPath;
    return [NSURL fileURLWithPath:path].URLByDeletingLastPathComponent;
}

- (void)showStartupPrompt {
    [self appendToConsole:[NSString stringWithFormat:@"Working directory: %@\n", self.workDir] color:self.ansiColors[7]];
    if (self.profiles.count == 0) {
        [self appendToConsole:@"No Liner profiles found. Add a .yaml file starting with `global:`.\n" color:self.ansiColors[3]];
        return;
    }

    if (self.selectedProfile) {
        [self appendToConsole:[NSString stringWithFormat:@"Selected profile: %@\n", self.selectedProfile] color:self.ansiColors[2]];
        [self appendToConsole:@"Choose Start from the status menu to run liner.\n" color:self.ansiColors[3]];
        return;
    }

    [self appendToConsole:@"Select a profile from Profiles, then choose Start to run liner.\n" color:self.ansiColors[3]];
}

- (NSImage *)makeTrayIcon {
    NSImage *image = [[NSImage alloc] initWithSize:NSMakeSize(18.0, 18.0)];
    [image lockFocus];
    [[NSColor blackColor] set];

    NSArray<NSArray<NSValue *> *> *paths = @[
        @[[NSValue valueWithPoint:NSMakePoint(4.5, 12.35)], [NSValue valueWithPoint:NSMakePoint(9.0, 12.35)], [NSValue valueWithPoint:NSMakePoint(13.5, 9.0)]],
        @[[NSValue valueWithPoint:NSMakePoint(4.5, 5.65)], [NSValue valueWithPoint:NSMakePoint(9.0, 5.65)], [NSValue valueWithPoint:NSMakePoint(13.5, 9.0)]],
    ];
    for (NSArray<NSValue *> *points in paths) {
        NSBezierPath *path = [NSBezierPath bezierPath];
        [path moveToPoint:points[0].pointValue];
        [path lineToPoint:points[1].pointValue];
        [path lineToPoint:points[2].pointValue];
        path.lineWidth = 2.1;
        path.lineCapStyle = NSLineCapStyleRound;
        path.lineJoinStyle = NSLineJoinStyleRound;
        [path stroke];
    }

    NSArray<NSValue *> *nodes = @[
        [NSValue valueWithPoint:NSMakePoint(4.5, 12.35)],
        [NSValue valueWithPoint:NSMakePoint(13.5, 9.0)],
        [NSValue valueWithPoint:NSMakePoint(4.5, 5.65)],
    ];
    for (NSValue *value in nodes) {
        NSPoint point = value.pointValue;
        [[NSBezierPath bezierPathWithOvalInRect:NSMakeRect(point.x - 2.35, point.y - 2.35, 4.7, 4.7)] fill];
    }

    [image unlockFocus];
    image.template = YES;
    return image;
}

- (void)setupStatusItem {
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength];
    self.statusItem.button.image = [self makeTrayIcon];
    self.statusItem.button.toolTip = self.appTitle;

    NSMenu *menu = [NSMenu new];
    menu.autoenablesItems = NO;
    [menu addItem:[self makeItem:@"Activity Log" action:@selector(showConsole:) symbol:@"macwindow"]];
    [menu addItem:NSMenuItem.separatorItem];

    NSMenuItem *profileItem = [[NSMenuItem alloc] initWithTitle:@"Profiles" action:nil keyEquivalent:@""];
    [self setItemSymbol:profileItem symbol:@"square.stack" description:@"Profiles"];
    self.profileMenu = [NSMenu new];
    profileItem.submenu = self.profileMenu;
    [self rebuildProfileMenu];
    [menu addItem:profileItem];

    NSMenuItem *networkItem = [[NSMenuItem alloc] initWithTitle:@"Network" action:nil keyEquivalent:@""];
    [self setItemSymbol:networkItem symbol:@"network" description:@"Network"];
    self.proxyMenu = [NSMenu new];
    self.proxyMenu.autoenablesItems = NO;
    self.proxyMenu.delegate = self;

    self.proxyDisableItem = [self makeItem:@"Disable" action:@selector(setProxyOff:) symbol:nil];
    [self.proxyMenu addItem:self.proxyDisableItem];
    self.proxyPACItem = [self makeItem:@"Auto Configuration (PAC)" action:@selector(setProxyPAC:) symbol:nil];
    [self.proxyMenu addItem:self.proxyPACItem];
    self.proxyManualItem = [self makeItem:@"Manual (HTTP/HTTPS)" action:@selector(setProxyHTTP:) symbol:nil];
    [self.proxyMenu addItem:self.proxyManualItem];

    networkItem.submenu = self.proxyMenu;
    [menu addItem:networkItem];
    [menu addItem:NSMenuItem.separatorItem];

    self.preferencesItem = [self makeItem:@"Preferences…" action:@selector(editConfig:) symbol:@"slider.horizontal.3"];
    [menu addItem:self.preferencesItem];
    self.idleDisplaySleepItem = [self makeItem:@"Prevent Display Sleep" action:@selector(toggleIdleDisplaySleep:) symbol:@"display"];
    [menu addItem:self.idleDisplaySleepItem];
    [menu addItem:NSMenuItem.separatorItem];

    self.startStopItem = [self makeItem:@"Start" action:@selector(startChildAction:) symbol:@"play.circle"];
    [menu addItem:self.startStopItem];
    [menu addItem:[self makeItem:@"Restart" action:@selector(reload:) symbol:@"arrow.clockwise"]];
    [menu addItem:NSMenuItem.separatorItem];
    [menu addItem:[self makeItem:[NSString stringWithFormat:@"Quit %@", self.appTitle] action:@selector(quit:) symbol:@"xmark.circle"]];

    self.statusItem.menu = menu;
    [self updateProxyMenuState];
    [self updateProfileMenuState];
    [self updatePreferencesMenuState];
    [self updateIdleDisplaySleepMenuState];
    [self updateProcessMenuState];
}

- (NSMenuItem *)makeItem:(NSString *)title action:(SEL)action symbol:(NSString *)symbol {
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:action keyEquivalent:@""];
    item.target = self;
    if (symbol) {
        [self setItemSymbol:item symbol:symbol description:title];
    }
    return item;
}

- (void)setItemSymbol:(NSMenuItem *)item symbol:(NSString *)symbol description:(NSString *)description {
    if ([NSImage respondsToSelector:@selector(imageWithSystemSymbolName:accessibilityDescription:)]) {
        NSImage *image = [NSImage imageWithSystemSymbolName:symbol accessibilityDescription:description];
        image.template = YES;
        item.image = image;
    }
}

- (void)menuNeedsUpdate:(NSMenu *)menu {
    if (menu == self.proxyMenu) {
        [self updateProxyMenuState];
    }
}

- (void)loadProfiles {
    self.profiles = [self scanProfiles];
    if (self.profiles.count == 1) {
        self.selectedProfile = self.profiles[0];
    } else if (self.selectedProfile && ![self.profiles containsObject:self.selectedProfile]) {
        self.selectedProfile = nil;
    }
}

- (NSArray<NSString *> *)scanProfiles {
    NSArray<NSString *> *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:self.workDir error:nil];
    entries = [entries sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray<NSString *> *profiles = [NSMutableArray array];
    for (NSString *entry in entries) {
        NSString *path = [self.workDir stringByAppendingPathComponent:entry];
        BOOL isDirectory = NO;
        if (![entry hasSuffix:@".yaml"] ||
            [entry isEqualToString:@"example.yaml"] ||
            ![[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDirectory] ||
            isDirectory ||
            ![self isLinerProfileFile:path]) {
            continue;
        }
        [profiles addObject:entry];
    }
    return profiles;
}

- (BOOL)isLinerProfileFile:(NSString *)path {
    NSString *content = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    if (!content) {
        return NO;
    }
    for (NSString *rawLine in [content componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        NSString *line = Trim(rawLine);
        if ([line hasPrefix:@"\ufeff"]) {
            line = [line substringFromIndex:1];
        }
        if (line.length == 0 || [line hasPrefix:@"#"]) {
            continue;
        }
        return [line hasPrefix:@"global:"];
    }
    return NO;
}

- (void)rebuildProfileMenu {
    if (!self.profileMenu) {
        return;
    }
    [self.profileMenu removeAllItems];
    [self.profileItems removeAllObjects];

    if (self.profiles.count == 0) {
        NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:@"No Liner Profiles" action:nil keyEquivalent:@""];
        item.enabled = NO;
        [self.profileMenu addItem:item];
        return;
    }

    for (NSString *profile in self.profiles) {
        NSMenuItem *item = [self makeItem:profile action:@selector(selectProfile:) symbol:nil];
        item.representedObject = profile;
        self.profileItems[profile] = item;
        [self.profileMenu addItem:item];
    }
    [self updateProfileMenuState];
}

- (void)updateProfileMenuState {
    for (NSString *profile in self.profileItems) {
        self.profileItems[profile].state = [profile isEqualToString:self.selectedProfile] ? NSControlStateValueOn : NSControlStateValueOff;
    }
    [self updatePreferencesMenuState];
}

- (void)updatePreferencesMenuState {
    self.preferencesItem.enabled = self.selectedProfile && self.profileItems[self.selectedProfile] != nil;
}

- (BOOL)isChildRunning {
    return self.childProcess && self.childProcess.isRunning;
}

- (ChildCommand *)childCommand {
    NSString *binPath = [self.workDir stringByAppendingPathComponent:self.childBin];
    if ([[NSFileManager defaultManager] fileExistsAtPath:binPath]) {
        if ([[NSFileManager defaultManager] isExecutableFileAtPath:binPath]) {
            return [ChildCommand commandWithExecutable:binPath arguments:@[] display:self.childBin];
        }
        [self appendToConsole:[NSString stringWithFormat:@"Cannot execute: %@\n", binPath] color:self.ansiColors[1]];
        return nil;
    }

    [self appendToConsole:[NSString stringWithFormat:@"Cannot find executable: %@\n", binPath] color:self.ansiColors[1]];
    return nil;
}

- (void)updateProcessMenuState {
    BOOL running = [self isChildRunning];
    self.statusItem.button.appearsDisabled = !running;

    if (!self.startStopItem) {
        return;
    }
    if (running) {
        self.startStopItem.title = @"Stop";
        self.startStopItem.action = @selector(stopChildAction:);
        [self setItemSymbol:self.startStopItem symbol:@"stop.circle" description:@"Stop"];
    } else {
        self.startStopItem.title = @"Start";
        self.startStopItem.action = @selector(startChildAction:);
        [self setItemSymbol:self.startStopItem symbol:@"play.circle" description:@"Start"];
    }
    self.startStopItem.target = self;
}

- (void)setupConsoleWindow {
    NSRect frame = NSMakeRect(0.0, 0.0, 800.0, 600.0);
    self.consoleWindow = [[NSWindow alloc] initWithContentRect:frame styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskResizable) backing:NSBackingStoreBuffered defer:NO];
    self.consoleWindow.title = self.logWindowTitle;
    self.consoleWindow.delegate = self;
    self.consoleWindow.releasedWhenClosed = NO;

    ConsoleBorderView *border = [[ConsoleBorderView alloc] initWithFrame:frame];
    border.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;

    NSRect scrollFrame = NSMakeRect(ConsoleBorderWidth, ConsoleBorderWidth, frame.size.width - ConsoleBorderWidth * 2.0, frame.size.height - ConsoleBorderWidth * 2.0);
    NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:scrollFrame];
    scroll.borderType = NSNoBorder;
    scroll.hasVerticalScroller = YES;
    scroll.hasHorizontalScroller = NO;
    scroll.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;

    self.consoleView = [[NSTextView alloc] initWithFrame:NSMakeRect(0.0, 0.0, scrollFrame.size.width, scrollFrame.size.height)];
    self.consoleView.backgroundColor = NSColor.blackColor;
    self.consoleView.richText = YES;
    self.consoleView.editable = NO;
    self.consoleView.verticallyResizable = YES;
    self.consoleView.horizontallyResizable = NO;
    self.consoleView.autoresizingMask = NSViewWidthSizable;
    self.consoleView.font = self.consoleFont;

    scroll.documentView = self.consoleView;
    [border addSubview:scroll];
    [self.consoleWindow.contentView addSubview:border];
}

- (NSArray<NSString *> *)configContents:(NSString *)configFile {
    NSString *configPath = [self.workDir stringByAppendingPathComponent:configFile];
    NSMutableArray<NSString *> *contents = [NSMutableArray array];
    for (NSString *path in [self configDataPaths:configPath]) {
        NSString *content = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
        if (content) {
            [contents addObject:content];
        }
    }
    return contents;
}

- (NSDictionary *)inspectProxyConfig {
    if (!self.selectedProfile) {
        return @{@"hasHTTP": @NO};
    }

    BOOL hasHTTP = NO;
    ProxySettings *settings = nil;
    NSString *pacLocation = nil;

    for (NSString *content in [self configContents:self.selectedProfile]) {
        NSString *listen = nil;
        BOOL foundHTTP = [self firstHTTPListen:content listen:&listen];
        hasHTTP = hasHTTP || foundHTTP;
        if (!settings && listen.length) {
            settings = [self proxySettingsFromListen:listen];
        }
        if (!pacLocation) {
            pacLocation = [self firstHTTPPACLocation:content];
        }
    }

    if (settings && pacLocation) {
        settings.pacURL = [self pacURLForHost:settings.host port:settings.port location:pacLocation];
    }
    return settings ? @{@"hasHTTP": @(hasHTTP), @"settings": settings} : @{@"hasHTTP": @(hasHTTP)};
}

- (BOOL)profileHasTunSection:(NSString *)configFile {
    for (NSString *content in [self configContents:configFile]) {
        if ([self yamlText:content hasTopLevelKey:@"tun"]) {
            return YES;
        }
    }
    return NO;
}

- (BOOL)yamlText:(NSString *)yamlText hasTopLevelKey:(NSString *)key {
    NSString *keyPrefix = [key stringByAppendingString:@":"];
    for (NSString *rawLine in [yamlText componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        if (Trim(rawLine).length == 0 || [TrimSpaces(rawLine) hasPrefix:@"#"]) {
            continue;
        }
        if ([self lineIndent:rawLine] != 0) {
            continue;
        }
        NSString *trimmed = Trim([self stripYAMLComment:rawLine]);
        if ([trimmed isEqualToString:keyPrefix] || [trimmed hasPrefix:[keyPrefix stringByAppendingString:@" "]]) {
            return YES;
        }
    }
    return NO;
}

- (NSString *)proxySettingsUnavailableTooltip {
    if (!self.selectedProfile) {
        return @"No profile selected";
    }
    NSDictionary *inspection = [self inspectProxyConfig];
    if (![inspection[@"hasHTTP"] boolValue]) {
        return @"No http: section in selected profile";
    }
    return @"No HTTP listen address found";
}

- (NSString *)proxyPACUnavailableTooltip {
    return @"No .pac web location in selected profile's http: section";
}

- (NSArray<NSString *> *)configDataPaths:(NSString *)configPath {
    NSString *base = [configPath stringByDeletingPathExtension];
    NSString *overlayDir = [base stringByAppendingPathExtension:@"d"];
    NSArray<NSString *> *entries = [[[NSFileManager defaultManager] contentsOfDirectoryAtPath:overlayDir error:nil] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray<NSString *> *paths = [NSMutableArray arrayWithObject:configPath];
    for (NSString *entry in entries) {
        if ([entry hasSuffix:@".yaml"]) {
            [paths addObject:[overlayDir stringByAppendingPathComponent:entry]];
        }
    }
    return paths;
}

- (BOOL)firstHTTPListen:(NSString *)yamlText listen:(NSString **)listenOut {
    BOOL inHTTP = NO;
    BOOL inListenBlock = NO;
    if (listenOut) {
        *listenOut = nil;
    }

    for (NSString *rawLine in [yamlText componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        NSString *trimmed = Trim(rawLine);
        if (trimmed.length == 0 || [trimmed hasPrefix:@"#"]) {
            continue;
        }

        if (!inHTTP) {
            if ([trimmed isEqualToString:@"http:"] || [trimmed hasPrefix:@"http: "]) {
                inHTTP = YES;
            }
            continue;
        }

        if (rawLine.length > 0 && ![[NSCharacterSet whitespaceCharacterSet] characterIsMember:[rawLine characterAtIndex:0]] && ![trimmed hasPrefix:@"- "]) {
            return YES;
        }

        if (inListenBlock) {
            if ([trimmed hasPrefix:@"- "]) {
                NSString *value = [self cleanYAMLScalar:[trimmed substringFromIndex:2]];
                if (value.length) {
                    if (listenOut) {
                        *listenOut = value;
                    }
                    return YES;
                }
            }
            inListenBlock = NO;
        }

        NSString *candidate = [trimmed hasPrefix:@"- "] ? TrimSpaces([trimmed substringFromIndex:2]) : trimmed;
        if (![candidate hasPrefix:@"listen:"]) {
            continue;
        }

        NSString *rawValue = TrimSpaces([candidate substringFromIndex:@"listen:".length]);
        if (rawValue.length == 0) {
            inListenBlock = YES;
        } else {
            if (listenOut) {
                *listenOut = [self firstListenScalar:rawValue];
            }
            return YES;
        }
    }

    return inHTTP;
}

- (NSString *)firstHTTPPACLocation:(NSString *)yamlText {
    __block BOOL inHTTP = NO;
    __block BOOL inWeb = NO;
    __block NSUInteger webIndent = 0;
    __block NSNumber *webItemIndent = nil;
    __block NSString *webLocation = nil;
    __block NSString *webFile = nil;
    __block BOOL webHasIndex = NO;

    NSString *(^flushWebItem)(void) = ^NSString *{
        if (webLocation.length == 0 || !webHasIndex) {
            return nil;
        }
        if ([self isPACLocation:webLocation] || (webFile && [self isPACLocation:webFile])) {
            return [self normalizeWebLocation:webLocation];
        }
        return nil;
    };

    for (NSString *rawLine in [yamlText componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
        NSString *trimmed = Trim(rawLine);
        if (trimmed.length == 0 || [trimmed hasPrefix:@"#"]) {
            continue;
        }

        NSUInteger indent = [self lineIndent:rawLine];
        if (!inHTTP) {
            if ([trimmed isEqualToString:@"http:"] || [trimmed hasPrefix:@"http: "]) {
                inHTTP = YES;
            }
            continue;
        }

        if (rawLine.length > 0 && ![[NSCharacterSet whitespaceCharacterSet] characterIsMember:[rawLine characterAtIndex:0]] && ![trimmed hasPrefix:@"- "]) {
            return flushWebItem();
        }

        if (inWeb && indent <= webIndent) {
            NSString *location = flushWebItem();
            if (location) {
                return location;
            }
            inWeb = NO;
            webItemIndent = nil;
            webLocation = nil;
            webFile = nil;
            webHasIndex = NO;
        }

        NSString *candidate = [trimmed hasPrefix:@"- "] ? TrimSpaces([trimmed substringFromIndex:2]) : trimmed;
        if (inWeb) {
            if ([trimmed hasPrefix:@"- "] && indent > webIndent) {
                if (!webItemIndent) {
                    webItemIndent = @(indent);
                }
                if (indent == webItemIndent.unsignedIntegerValue) {
                    NSString *location = flushWebItem();
                    if (location) {
                        return location;
                    }
                    webLocation = nil;
                    webFile = nil;
                    webHasIndex = NO;
                    candidate = TrimSpaces([trimmed substringFromIndex:2]);
                }
            }

            if ([candidate hasPrefix:@"location:"]) {
                webLocation = [self cleanYAMLScalar:TrimSpaces([candidate substringFromIndex:@"location:".length])];
            } else if ([candidate hasPrefix:@"index:"]) {
                webHasIndex = YES;
            } else if ([candidate hasPrefix:@"file:"]) {
                webFile = [self cleanYAMLScalar:TrimSpaces([candidate substringFromIndex:@"file:".length])];
            }

            NSString *location = flushWebItem();
            if (location) {
                return location;
            }
            continue;
        }

        if ([candidate hasPrefix:@"web:"]) {
            inWeb = YES;
            webIndent = indent;
            webItemIndent = nil;
            webLocation = nil;
            webFile = nil;
            webHasIndex = NO;
        }
    }

    return inHTTP ? flushWebItem() : nil;
}

- (NSUInteger)lineIndent:(NSString *)rawLine {
    NSUInteger index = 0;
    NSCharacterSet *whitespace = [NSCharacterSet whitespaceCharacterSet];
    while (index < rawLine.length && [whitespace characterIsMember:[rawLine characterAtIndex:index]]) {
        index++;
    }
    return index;
}

- (NSString *)normalizeWebLocation:(NSString *)location {
    return [location hasPrefix:@"/"] ? location : [@"/" stringByAppendingString:location];
}

- (BOOL)isPACLocation:(NSString *)location {
    NSString *path = [[location componentsSeparatedByString:@"?"].firstObject lowercaseString];
    return [path hasSuffix:@".pac"];
}

- (NSString *)pacURLForHost:(NSString *)host port:(NSString *)port location:(NSString *)location {
    return [NSString stringWithFormat:@"http://%@:%@%@", [ProxySettings urlHost:host], port, [self normalizeWebLocation:location]];
}

- (NSString *)firstListenScalar:(NSString *)raw {
    NSString *value = [self stripYAMLComment:raw];
    if ([value hasPrefix:@"["] && [value hasSuffix:@"]"]) {
        value = [value stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"[]"]];
        value = [value componentsSeparatedByString:@","].firstObject ?: @"";
    }
    return [self cleanYAMLScalar:value];
}

- (NSString *)cleanYAMLScalar:(NSString *)raw {
    NSString *value = [self stripYAMLComment:raw];
    if (value.length == 0 || [value isEqualToString:@"|"] || [value isEqualToString:@">"]) {
        return nil;
    }
    return Trim([self stripMatchingQuotes:value]);
}

- (NSString *)stripYAMLComment:(NSString *)raw {
    NSRange range = [raw rangeOfString:@"#"];
    NSString *value = range.location == NSNotFound ? raw : [raw substringToIndex:range.location];
    return Trim(value);
}

- (NSString *)stripMatchingQuotes:(NSString *)value {
    if (value.length >= 2) {
        unichar first = [value characterAtIndex:0];
        unichar last = [value characterAtIndex:value.length - 1];
        if (first == last && (first == '\'' || first == '"')) {
            return [value substringWithRange:NSMakeRange(1, value.length - 2)];
        }
    }
    return value;
}

- (ProxySettings *)proxySettingsFromListen:(NSString *)rawListen {
    NSString *listen = Trim(rawListen);
    NSRange scheme = [listen rangeOfString:@"://"];
    if (scheme.location != NSNotFound) {
        listen = [listen substringFromIndex:NSMaxRange(scheme)];
    }
    NSRange slash = [listen rangeOfString:@"/"];
    if (slash.location != NSNotFound) {
        listen = [listen substringToIndex:slash.location];
    }
    NSRange question = [listen rangeOfString:@"?"];
    if (question.location != NSNotFound) {
        listen = [listen substringToIndex:question.location];
    }

    NSString *host = nil;
    NSString *port = nil;
    if ([listen hasPrefix:@"["]) {
        NSRange close = [listen rangeOfString:@"]"];
        if (close.location == NSNotFound) {
            return nil;
        }
        host = [listen substringWithRange:NSMakeRange(1, close.location - 1)];
        NSString *rest = [listen substringFromIndex:NSMaxRange(close)];
        if (![rest hasPrefix:@":"]) {
            return nil;
        }
        port = [rest substringFromIndex:1];
    } else {
        NSRange colon = [listen rangeOfString:@":" options:NSBackwardsSearch];
        if (colon.location != NSNotFound) {
            host = [listen substringToIndex:colon.location];
            port = [listen substringFromIndex:NSMaxRange(colon)];
        } else if ([self isASCIIDigits:listen]) {
            host = @"";
            port = listen;
        } else {
            return nil;
        }
    }

    NSInteger portNumber = 0;
    if (![self parsePort:port value:&portNumber]) {
        return nil;
    }
    return [ProxySettings settingsWithHost:[self proxyHostForListenHost:host] port:[NSString stringWithFormat:@"%ld", (long)portNumber]];
}

- (BOOL)parsePort:(NSString *)port value:(NSInteger *)value {
    NSString *text = Trim(port ?: @"");
    if (text.length == 0) {
        return NO;
    }
    NSScanner *scanner = [NSScanner scannerWithString:text];
    scanner.charactersToBeSkipped = nil;
    long long scanned = 0;
    if (![scanner scanLongLong:&scanned] || !scanner.isAtEnd || scanned < 1 || scanned > 65535) {
        return NO;
    }
    if (value) {
        *value = (NSInteger)scanned;
    }
    return YES;
}

- (BOOL)isASCIIDigits:(NSString *)value {
    if (value.length == 0) {
        return NO;
    }
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar c = [value characterAtIndex:i];
        if (c < '0' || c > '9') {
            return NO;
        }
    }
    return YES;
}

- (NSString *)proxyHostForListenHost:(NSString *)host {
    NSString *trimmed = Trim(host ?: @"");
    if (trimmed.length == 0 || [trimmed isEqualToString:@"*"] || [trimmed isEqualToString:@"0.0.0.0"] || [trimmed isEqualToString:@"::"] || [trimmed isEqualToString:@"::0"]) {
        return @"127.0.0.1";
    }
    return trimmed;
}

- (BOOL)startChild {
    [self appendToConsole:[NSString stringWithFormat:@"Working directory: %@\n", self.workDir] color:self.ansiColors[7]];
    if ([self isChildRunning]) {
        [self appendToConsole:[NSString stringWithFormat:@"%@ is already running.\n", self.childBin] color:self.ansiColors[3]];
        [self updateProcessMenuState];
        [self updateProxyMenuState];
        return YES;
    }

    ChildCommand *command = [self childCommand];
    if (!command) {
        [self updateProcessMenuState];
        return NO;
    }

    NSString *configFile = self.selectedProfile;
    if (!configFile) {
        [self appendToConsole:@"No profile selected. Choose one from Profiles in the status menu.\n" color:self.ansiColors[1]];
        [self updateProcessMenuState];
        return NO;
    }

    NSString *configPath = [self.workDir stringByAppendingPathComponent:configFile];
    if (![[NSFileManager defaultManager] fileExistsAtPath:configPath]) {
        [self appendToConsole:[NSString stringWithFormat:@"Config file not found: %@\n", configPath] color:self.ansiColors[1]];
        [self updateProcessMenuState];
        return NO;
    }

    NSMutableDictionary *environment = [NSMutableDictionary dictionaryWithDictionary:NSProcessInfo.processInfo.environment];
    environment[@"LINER_LOG_TO_STDERR"] = @"1";

    BOOL requiresAdmin = [self profileHasTunSection:configFile];
    if (requiresAdmin && ![self sudoCredentialsAvailable:environment]) {
        if (![self confirmTunAdmin]) {
            [self appendToConsole:@"Start canceled.\n" color:self.ansiColors[3]];
            [self updateProcessMenuState];
            return NO;
        }

        [self appendToConsole:@"Requesting administrator authorization for TUN.\n" color:self.ansiColors[3]];
        NSDictionary *result = [self authorizeSudo:environment];
        if (![result[@"ok"] boolValue]) {
            NSString *message = result[@"message"];
            if (message.length) {
                [self appendToConsole:[NSString stringWithFormat:@"Administrator authorization failed: %@\n", message] color:self.ansiColors[1]];
            } else {
                [self appendToConsole:@"Administrator authorization failed.\n" color:self.ansiColors[1]];
            }
            [self updateProcessMenuState];
            return NO;
        }
    }

    if (requiresAdmin) {
        [self appendToConsole:[NSString stringWithFormat:@"Starting with sudo: %@ %@\n", command.display, configFile] color:self.ansiColors[2]];
    } else {
        [self appendToConsole:[NSString stringWithFormat:@"Starting: %@ %@\n", command.display, configFile] color:self.ansiColors[2]];
    }

    NSTask *task = [NSTask new];
    NSPipe *stdoutPipe = [NSPipe pipe];
    NSPipe *stderrPipe = [NSPipe pipe];
    task.currentDirectoryPath = self.workDir;
    task.environment = environment;
    task.standardInput = NSFileHandle.fileHandleWithNullDevice;
    task.standardOutput = stdoutPipe;
    task.standardError = stderrPipe;

    if (requiresAdmin) {
        task.launchPath = @"/usr/bin/sudo";
        NSMutableArray<NSString *> *args = [NSMutableArray arrayWithArray:@[@"-n", @"--", @"/usr/bin/env", @"LINER_LOG_TO_STDERR=1", command.executable]];
        [args addObjectsFromArray:command.arguments];
        [args addObject:configFile];
        task.arguments = args;
    } else {
        task.launchPath = command.executable;
        task.arguments = [command.arguments arrayByAddingObject:configFile];
    }

    [self startReading:stdoutPipe];
    [self startReading:stderrPipe];
    __weak typeof(self) weakSelf = self;
    task.terminationHandler = ^(NSTask *finishedTask) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [weakSelf childDidTerminate:finishedTask];
        });
    };
    self.childProcess = task;

    NSError *error = nil;
    if (![task launchAndReturnError:&error]) {
        if (self.childProcess == task) {
            self.childProcess = nil;
        }
        stdoutPipe.fileHandleForReading.readabilityHandler = nil;
        stderrPipe.fileHandleForReading.readabilityHandler = nil;
        [self appendToConsole:[NSString stringWithFormat:@"Failed to start %@: %@\n", self.childBin, error.localizedDescription] color:self.ansiColors[1]];
        [self updateProcessMenuState];
        return NO;
    }

    [self updateProcessMenuState];
    [self updateProxyMenuState];
    return YES;
}

- (BOOL)sudoCredentialsAvailable:(NSDictionary<NSString *, NSString *> *)environment {
    NSDictionary *result = [self runSync:@"/usr/bin/sudo" arguments:@[@"-n", @"true"] environment:environment captureStderr:NO error:nil];
    return result && [result[@"status"] intValue] == 0;
}

- (NSDictionary *)runSync:(NSString *)executable arguments:(NSArray<NSString *> *)arguments environment:(NSDictionary<NSString *, NSString *> *)environment captureStderr:(BOOL)captureStderr error:(NSError **)error {
    NSTask *task = [NSTask new];
    NSPipe *stderrPipe = captureStderr ? [NSPipe pipe] : nil;
    task.launchPath = executable;
    task.arguments = arguments;
    task.currentDirectoryPath = self.workDir;
    task.environment = environment;
    task.standardInput = NSFileHandle.fileHandleWithNullDevice;
    task.standardOutput = NSFileHandle.fileHandleWithNullDevice;
    task.standardError = stderrPipe ? stderrPipe : NSFileHandle.fileHandleWithNullDevice;

    if (![task launchAndReturnError:error]) {
        return nil;
    }
    [task waitUntilExit];

    NSString *stderrText = @"";
    if (stderrPipe) {
        NSData *data = [stderrPipe.fileHandleForReading readDataToEndOfFile];
        stderrText = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
    }
    return @{@"status": @(task.terminationStatus), @"stderr": stderrText};
}

- (BOOL)confirmTunAdmin {
    NSAlert *alert = [NSAlert new];
    alert.messageText = @"TUN Requires Administrator Privileges";
    alert.informativeText = @"The selected profile contains a tun: section. Liner needs administrator privileges to create and configure the TUN interface.";
    [alert addButtonWithTitle:@"Continue"];
    [alert addButtonWithTitle:@"Cancel"];
    [NSApp activateIgnoringOtherApps:YES];
    return [alert runModal] == NSAlertFirstButtonReturn;
}

- (NSDictionary *)authorizeSudo:(NSDictionary<NSString *, NSString *> *)environment {
    NSMutableDictionary *authEnvironment = [NSMutableDictionary dictionaryWithDictionary:environment];
    authEnvironment[@"SUDO_ASKPASS"] = [self ensureSudoAskpass];

    NSError *error = nil;
    NSDictionary *result = [self runSync:@"/usr/bin/sudo"
                               arguments:@[@"-A", @"-v", @"-p", [NSString stringWithFormat:@"%@ needs administrator privileges to start TUN.\nPassword: ", self.appTitle]]
                             environment:authEnvironment
                           captureStderr:YES
                                    error:&error];
    if (!result) {
        return @{@"ok": @NO, @"message": error.localizedDescription ?: @""};
    }
    if ([result[@"status"] intValue] != 0) {
        return @{@"ok": @NO, @"message": [self cleanProcessError:result[@"stderr"]]};
    }
    if (![self sudoCredentialsAvailable:environment]) {
        return @{@"ok": @NO, @"message": @"sudo credentials were not cached"};
    }
    return @{@"ok": @YES, @"message": @""};
}

- (NSString *)cleanProcessError:(NSString *)message {
    if (message.length == 0) {
        return @"";
    }
    NSArray<NSString *> *parts = [Trim(message) componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSPredicate *notEmpty = [NSPredicate predicateWithBlock:^BOOL(NSString *part, NSDictionary *bindings) {
        return part.length > 0;
    }];
    return [[parts filteredArrayUsingPredicate:notEmpty] componentsJoinedByString:@" "];
}

- (NSString *)ensureSudoAskpass {
    if (self.sudoAskpassPath && [[NSFileManager defaultManager] fileExistsAtPath:self.sudoAskpassPath]) {
        return self.sudoAskpassPath;
    }

    NSString *script = @"#!/bin/sh\n"
        "prompt=${1:-\"Password:\"}\n"
        "exec /usr/bin/osascript - \"$prompt\" <<'APPLESCRIPT'\n"
        "on run argv\n"
        "    set promptText to item 1 of argv\n"
        "    try\n"
        "        set dialogResult to display dialog promptText default answer \"\" with hidden answer buttons {\"OK\", \"Cancel\"} default button \"OK\" with title \"Liner\" with icon caution\n"
        "        return text returned of dialogResult\n"
        "    on error number -128\n"
        "        error number -128\n"
        "    end try\n"
        "end run\n"
        "APPLESCRIPT\n";

    NSString *templatePath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"%@-askpass-XXXXXX.sh", self.childBin]];
    char *pathBuffer = strdup(templatePath.fileSystemRepresentation);
    if (!pathBuffer) {
        [self appendToConsole:@"Failed to create askpass helper: out of memory\n" color:self.ansiColors[1]];
        return @"/usr/bin/false";
    }

    int fd = mkstemps(pathBuffer, 3);
    if (fd == -1) {
        NSString *message = [NSString stringWithUTF8String:strerror(errno)] ?: @"unknown error";
        [self appendToConsole:[NSString stringWithFormat:@"Failed to create askpass helper: %@\n", message] color:self.ansiColors[1]];
        free(pathBuffer);
        return @"/usr/bin/false";
    }

    NSData *data = [script dataUsingEncoding:NSUTF8StringEncoding];
    const uint8_t *bytes = data.bytes;
    NSUInteger remaining = data.length;
    BOOL ok = YES;
    while (remaining > 0) {
        ssize_t n = write(fd, bytes, remaining);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ok = NO;
            break;
        }
        if (n == 0) {
            errno = EIO;
            ok = NO;
            break;
        }
        bytes += n;
        remaining -= (NSUInteger)n;
    }
    if (close(fd) != 0) {
        ok = NO;
    }

    NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathBuffer length:strlen(pathBuffer)];
    if (!ok) {
        NSString *message = [NSString stringWithUTF8String:strerror(errno)] ?: @"unknown error";
        [self appendToConsole:[NSString stringWithFormat:@"Failed to create askpass helper: %@\n", message] color:self.ansiColors[1]];
        [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
        free(pathBuffer);
        return @"/usr/bin/false";
    }
    free(pathBuffer);

    chmod(path.fileSystemRepresentation, S_IRWXU);
    self.sudoAskpassPath = path;
    return path;
}

- (void)cleanupSudoAskpass {
    NSString *path = self.sudoAskpassPath;
    self.sudoAskpassPath = nil;
    if (path.length) {
        [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    }
}

- (void)startReading:(NSPipe *)pipe {
    NSFileHandle *handle = pipe.fileHandleForReading;
    __weak typeof(self) weakSelf = self;
    handle.readabilityHandler = ^(NSFileHandle *readHandle) {
        NSData *data = readHandle.availableData;
        if (data.length == 0) {
            readHandle.readabilityHandler = nil;
            return;
        }
        NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding] ?: @"";
        dispatch_async(dispatch_get_main_queue(), ^{
            [weakSelf handleIncoming:text];
        });
    };
}

- (void)installSignalHandlers {
    for (NSNumber *signalNumber in @[@(SIGINT), @(SIGTERM)]) {
        int signum = signalNumber.intValue;
        signal(signum, SIG_IGN);
        dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, (uintptr_t)signum, 0, dispatch_get_main_queue());
        __weak typeof(self) weakSelf = self;
        dispatch_source_set_event_handler(source, ^{
            [weakSelf terminateFromSignal:signum];
        });
        dispatch_resume(source);
        [self.signalSources addObject:source];
    }
}

- (void)terminateFromSignal:(int)signum {
    if (self.terminatingFromSignal) {
        return;
    }
    self.terminatingFromSignal = YES;
    [self appendToConsole:[NSString stringWithFormat:@"\nReceived signal %d, stopping %@...\n", signum, self.childBin] color:self.ansiColors[3]];
    [self stopChild];
    [NSApp terminate:nil];
}

- (BOOL)stopChild {
    NSTask *task = self.childProcess;
    if (!task) {
        [self updateProcessMenuState];
        [self updateProxyMenuState];
        return YES;
    }

    [self.expectedTerminationPIDs addObject:@(task.processIdentifier)];
    if (task.isRunning) {
        [task terminate];
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:ChildStopTimeout];
        while (task.isRunning && [deadline timeIntervalSinceNow] > 0) {
            [NSThread sleepForTimeInterval:0.05];
        }
        if (task.isRunning) {
            [self appendToConsole:[NSString stringWithFormat:@"%@ did not exit after %ds; killing it.\n", self.childBin, (int)ChildStopTimeout] color:self.ansiColors[3]];
            kill(task.processIdentifier, SIGKILL);
            NSDate *killDeadline = [NSDate dateWithTimeIntervalSinceNow:2.0];
            while (task.isRunning && [killDeadline timeIntervalSinceNow] > 0) {
                [NSThread sleepForTimeInterval:0.05];
            }
        }
    }

    BOOL stopped = !task.isRunning;
    if (self.childProcess == task && stopped) {
        self.childProcess = nil;
    }
    [self updateProcessMenuState];
    [self updateProxyMenuState];
    return stopped;
}

- (void)childDidTerminate:(NSTask *)task {
    NSNumber *pid = @(task.processIdentifier);
    BOOL expected = [self.expectedTerminationPIDs containsObject:pid];
    [self.expectedTerminationPIDs removeObject:pid];
    if (self.childProcess == task) {
        self.childProcess = nil;
    }
    [self updateProcessMenuState];
    [self updateProxyMenuState];
    if (expected) {
        return;
    }

    NSString *reason = task.terminationReason == NSTaskTerminationReasonUncaughtSignal
        ? [NSString stringWithFormat:@"signal %d", task.terminationStatus]
        : [NSString stringWithFormat:@"exit status %d", task.terminationStatus];
    [self appendToConsole:[NSString stringWithFormat:@"\n%@ exited unexpectedly: %@\n", self.childBin, reason] color:self.ansiColors[1]];
    self.statusItem.button.toolTip = [NSString stringWithFormat:@"%@ stopped: %@", self.appTitle, reason];
    [self showConsole:nil];
    [self sendNotificationWithTitle:self.appTitle body:[NSString stringWithFormat:@"%@ stopped: %@", self.childBin, reason]];
}

- (void)applyANSICodes:(NSString *)codeString {
    NSArray<NSString *> *parts = codeString.length ? [codeString componentsSeparatedByString:@";"] : @[@""];
    for (NSString *part in parts) {
        NSInteger code = part.integerValue;
        if (code >= 30 && code < 38) {
            self.currentColor = self.ansiColors[code - 30];
        } else if (code == 0 || code == 39) {
            self.currentColor = self.ansiColors[0];
        }
    }
}

- (void)handleIncoming:(NSString *)raw {
    NSMutableString *line = raw.mutableCopy;
    while (YES) {
        NSRange esc = [line rangeOfString:@"\033]2;"];
        if (esc.location == NSNotFound) {
            break;
        }
        NSRange searchRange = NSMakeRange(NSMaxRange(esc), line.length - NSMaxRange(esc));
        NSRange bell = [line rangeOfString:@"\a" options:0 range:searchRange];
        if (bell.location == NSNotFound) {
            break;
        }
        NSString *title = [line substringWithRange:NSMakeRange(NSMaxRange(esc), bell.location - NSMaxRange(esc))];
        self.statusItem.button.toolTip = title;
        self.consoleWindow.title = title;
        [line deleteCharactersInRange:NSMakeRange(esc.location, NSMaxRange(bell) - esc.location)];
    }

    NSUInteger index = 0;
    NSMutableString *pending = [NSMutableString string];
    while (index < line.length) {
        if ([line characterAtIndex:index] == 0x1b && index + 1 < line.length && [line characterAtIndex:index + 1] == '[') {
            NSUInteger codeStart = index + 2;
            NSRange searchRange = NSMakeRange(codeStart, line.length - codeStart);
            NSRange m = [line rangeOfString:@"m" options:0 range:searchRange];
            if (m.location != NSNotFound) {
                if (pending.length) {
                    [self appendToConsole:pending color:self.currentColor];
                    [pending setString:@""];
                }
                [self applyANSICodes:[line substringWithRange:NSMakeRange(codeStart, m.location - codeStart)]];
                index = NSMaxRange(m);
                continue;
            }
        }
        [pending appendFormat:@"%C", [line characterAtIndex:index]];
        index++;
    }
    if (pending.length) {
        [self appendToConsole:pending color:self.currentColor];
    }
}

- (void)appendToConsole:(NSString *)text color:(NSColor *)color {
    if (!self.consoleView.textStorage) {
        return;
    }
    NSRect visible = self.consoleView.visibleRect;
    NSRect bounds = self.consoleView.bounds;
    BOOL shouldScroll = NSMaxY(visible) >= NSMaxY(bounds) - 20.0;
    NSDictionary *attrs = @{NSForegroundColorAttributeName: color, NSFontAttributeName: self.consoleFont};
    [self.consoleView.textStorage appendAttributedString:[[NSAttributedString alloc] initWithString:text attributes:attrs]];
    [self trimConsoleIfNeeded];
    if (shouldScroll) {
        [self.consoleView scrollRangeToVisible:NSMakeRange(self.consoleView.textStorage.length, 0)];
    }
}

- (void)trimConsoleIfNeeded {
    NSTextStorage *storage = self.consoleView.textStorage;
    NSInteger overflow = (NSInteger)storage.length - (NSInteger)ConsoleMaxLength;
    if (overflow <= 0) {
        return;
    }
    NSUInteger deleteLength = MIN(storage.length, (NSUInteger)overflow + ConsoleTrimExtra);
    if (deleteLength < storage.length) {
        NSRange searchRange = NSMakeRange(deleteLength, MIN((NSUInteger)4096, storage.length - deleteLength));
        NSRange newline = [storage.string rangeOfString:@"\n" options:0 range:searchRange];
        if (newline.location != NSNotFound) {
            deleteLength = NSMaxRange(newline);
        }
    }
    [storage deleteCharactersInRange:NSMakeRange(0, deleteLength)];
}

- (void)sendNotificationWithTitle:(NSString *)title body:(NSString *)body {
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdeprecated-declarations"
    NSUserNotification *notification = [NSUserNotification new];
    notification.title = title;
    notification.informativeText = body;
    notification.soundName = NSUserNotificationDefaultSoundName;
    [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:notification];
    #pragma clang diagnostic pop
}

- (void)showConsole:(id)sender {
    [self.consoleWindow center];
    [self.consoleWindow makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)setProxyOff:(id)sender {
    [self applyProxyMode:@"off"];
}

- (void)setProxyPAC:(id)sender {
    [self applyProxyMode:@"pac"];
}

- (void)setProxyHTTP:(id)sender {
    [self applyProxyMode:@"http"];
}

- (void)toggleIdleDisplaySleep:(id)sender {
    if (self.idleDisplaySleepActivity) {
        [self endIdleDisplaySleepActivity];
        [self appendToConsole:@"Prevent display sleep disabled.\n" color:self.ansiColors[3]];
        return;
    }

    self.idleDisplaySleepActivity = [[NSProcessInfo processInfo] beginActivityWithOptions:NSActivityIdleDisplaySleepDisabled reason:self.appTitle];
    [self updateIdleDisplaySleepMenuState];
    [self appendToConsole:@"Prevent display sleep enabled.\n" color:self.ansiColors[2]];
}

- (void)endIdleDisplaySleepActivity {
    id activity = self.idleDisplaySleepActivity;
    if (!activity) {
        return;
    }
    self.idleDisplaySleepActivity = nil;
    [[NSProcessInfo processInfo] endActivity:activity];
    [self updateIdleDisplaySleepMenuState];
}

- (void)updateIdleDisplaySleepMenuState {
    self.idleDisplaySleepItem.state = self.idleDisplaySleepActivity ? NSControlStateValueOn : NSControlStateValueOff;
}

- (void)selectProfile:(NSMenuItem *)sender {
    NSString *profile = sender.representedObject;
    if (!profile) {
        return;
    }
    if (![self.profiles containsObject:profile]) {
        [self appendToConsole:[NSString stringWithFormat:@"Profile not found: %@\n", profile] color:self.ansiColors[1]];
        [self rebuildProfileMenu];
        return;
    }
    self.selectedProfile = profile;
    [self updateProfileMenuState];
    [self updateProxyMenuState];
    [self appendToConsole:[NSString stringWithFormat:@"Selected profile: %@\n", profile] color:self.ansiColors[2]];
    if ([self isChildRunning]) {
        [self appendToConsole:@"Restart liner to apply the selected profile.\n" color:self.ansiColors[3]];
    }
}

- (void)editConfig:(id)sender {
    NSString *configFile = self.selectedProfile;
    if (!configFile) {
        [self appendToConsole:@"No profile selected. Choose one from Profiles in the status menu.\n" color:self.ansiColors[1]];
        [self showConsole:nil];
        return;
    }

    NSString *configPath = [self.workDir stringByAppendingPathComponent:configFile];
    if (![[NSFileManager defaultManager] fileExistsAtPath:configPath]) {
        [self appendToConsole:[NSString stringWithFormat:@"Config file not found: %@\n", configPath] color:self.ansiColors[1]];
        [self showConsole:nil];
        return;
    }

    NSURL *configURL = [NSURL fileURLWithPath:configPath];
    NSURL *textEditURL = [[NSWorkspace sharedWorkspace] URLForApplicationWithBundleIdentifier:@"com.apple.TextEdit"];
    NSWorkspaceOpenConfiguration *configuration = [NSWorkspaceOpenConfiguration configuration];
    [[NSWorkspace sharedWorkspace] openURLs:@[configURL] withApplicationAtURL:textEditURL configuration:configuration completionHandler:^(NSRunningApplication *app, NSError *error) {
        if (!error) {
            return;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            [self appendToConsole:[NSString stringWithFormat:@"Open config failed: %@\n", configPath] color:self.ansiColors[1]];
            [self showConsole:nil];
        });
    }];
}

- (void)reload:(id)sender {
    [self showConsole:sender];
    if (![self stopChild]) {
        [self appendToConsole:[NSString stringWithFormat:@"Restart aborted: %@ is still running.\n", self.childBin] color:self.ansiColors[1]];
        return;
    }
    self.consoleView.string = @"";
    if ([self startChild]) {
        [self sendNotificationWithTitle:self.appTitle body:@"Restarted."];
    } else {
        [self showConsole:nil];
        [self sendNotificationWithTitle:self.appTitle body:@"Restart failed. Check the activity log."];
    }
}

- (void)startChildAction:(id)sender {
    [self showConsole:sender];
    if ([self startChild]) {
        [self sendNotificationWithTitle:self.appTitle body:@"Started."];
    } else {
        [self showConsole:nil];
        [self sendNotificationWithTitle:self.appTitle body:@"Failed to start. Check the activity log."];
    }
}

- (void)stopChildAction:(id)sender {
    [self showConsole:sender];
    if ([self stopChild]) {
        [self appendToConsole:[NSString stringWithFormat:@"%@ stopped.\n", self.childBin] color:self.ansiColors[3]];
    } else {
        [self appendToConsole:[NSString stringWithFormat:@"Failed to stop %@.\n", self.childBin] color:self.ansiColors[1]];
    }
}

- (void)quit:(id)sender {
    [self stopChild];
    [NSApp terminate:nil];
}

- (void)applyProxyMode:(NSString *)mode {
    ProxySettings *settings = nil;
    NSString *modeName = nil;

    if ([mode isEqualToString:@"off"]) {
        modeName = @"Disable";
    } else {
        if (![self isChildRunning]) {
            [self updateProxyMenuState];
            [self appendToConsole:[NSString stringWithFormat:@"System proxy mode unavailable: %@ is not running.\n", self.childBin] color:self.ansiColors[1]];
            [self showConsole:nil];
            return;
        }
        settings = [self inspectProxyConfig][@"settings"];
        if (!settings || ([mode isEqualToString:@"pac"] && !settings.pacURL)) {
            [self updateProxyMenuState];
            [self appendToConsole:@"System proxy mode unavailable: selected profile has no usable proxy endpoint.\n" color:self.ansiColors[1]];
            [self showConsole:nil];
            return;
        }
        modeName = [mode isEqualToString:@"pac"]
            ? [NSString stringWithFormat:@"PAC %@", settings.pacURL]
            : [NSString stringWithFormat:@"HTTP/HTTPS %@", settings.address];
    }

    @try {
        NSArray<NSString *> *services = [self setSystemProxy:mode settings:settings];
        [self updateProxyMenuState];
        [self appendToConsole:[NSString stringWithFormat:@"Applied System Proxy '%@' to: %@\n", modeName, [services componentsJoinedByString:@", "]] color:self.ansiColors[2]];
    } @catch (NSException *exception) {
        [self appendToConsole:[NSString stringWithFormat:@"System proxy update failed: %@\n", exception.reason] color:self.ansiColors[1]];
        [self showConsole:nil];
    }
}

- (void)updateProxyMenuState {
    if (!self.proxyDisableItem || !self.proxyPACItem || !self.proxyManualItem) {
        return;
    }

    BOOL running = [self isChildRunning];
    ProxySettings *settings = running ? [self inspectProxyConfig][@"settings"] : nil;
    self.proxyPACItem.enabled = running && settings.pacURL != nil;
    self.proxyManualItem.enabled = running && settings != nil;

    if (!running) {
        NSString *tooltip = [NSString stringWithFormat:@"%@ is not running", self.childBin];
        self.proxyPACItem.toolTip = tooltip;
        self.proxyManualItem.toolTip = tooltip;
    } else if (settings) {
        self.proxyPACItem.toolTip = settings.pacURL ?: [self proxyPACUnavailableTooltip];
        self.proxyManualItem.toolTip = settings.address;
    } else {
        NSString *tooltip = [self proxySettingsUnavailableTooltip];
        self.proxyPACItem.toolTip = tooltip;
        self.proxyManualItem.toolTip = tooltip;
    }

    NSString *mode = nil;
    @try {
        mode = [self currentSystemProxyMode];
    } @catch (NSException *exception) {
    }
    self.proxyDisableItem.state = [mode isEqualToString:@"off"] ? NSControlStateValueOn : NSControlStateValueOff;
    self.proxyPACItem.state = [mode isEqualToString:@"pac"] ? NSControlStateValueOn : NSControlStateValueOff;
    self.proxyManualItem.state = [mode isEqualToString:@"http"] ? NSControlStateValueOn : NSControlStateValueOff;
}

- (NSString *)currentSystemProxyMode {
    id prefsObj = CFBridgingRelease(SCPreferencesCreate(NULL, (__bridge CFStringRef)self.appTitle, NULL));
    if (!prefsObj) {
        @throw [self scError:@"open network preferences"];
    }
    SCPreferencesRef prefs = (__bridge SCPreferencesRef)prefsObj;
    NSString *primaryServiceID = [self currentPrimaryServiceID];
    NSMutableArray<NSString *> *serviceModes = [NSMutableArray array];

    for (NSDictionary *entry in [self enabledProxyProtocols:prefs]) {
        SCNetworkServiceRef service = (__bridge SCNetworkServiceRef)entry[@"service"];
        SCNetworkProtocolRef proto = (__bridge SCNetworkProtocolRef)entry[@"proto"];
        NSString *mode = [self proxyModeFromConfig:[self proxyConfigFromProtocol:proto]];
        [serviceModes addObject:mode];

        if (primaryServiceID.length) {
            CFStringRef serviceID = SCNetworkServiceGetServiceID(service);
            if (serviceID && [(__bridge NSString *)serviceID isEqualToString:primaryServiceID]) {
                return mode;
            }
        }
    }

    if (serviceModes.count == 0) {
        return nil;
    }
    NSSet *uniqueModes = [NSSet setWithArray:serviceModes];
    if (uniqueModes.count == 1) {
        return serviceModes[0];
    }
    NSMutableSet *enabledModes = [NSMutableSet setWithArray:serviceModes];
    [enabledModes removeObject:@"off"];
    if (enabledModes.count == 1) {
        return enabledModes.anyObject;
    }
    return @"mixed";
}

- (NSArray<NSDictionary *> *)enabledProxyProtocols:(SCPreferencesRef)prefs {
    id networkSetObj = CFBridgingRelease(SCNetworkSetCopyCurrent(prefs));
    if (!networkSetObj) {
        @throw [self scError:@"read current network set"];
    }
    id servicesObj = CFBridgingRelease(SCNetworkSetCopyServices((__bridge SCNetworkSetRef)networkSetObj));
    if (!servicesObj) {
        @throw [self scError:@"read network services"];
    }

    NSMutableArray<NSDictionary *> *entries = [NSMutableArray array];
    for (id serviceObj in (NSArray *)servicesObj) {
        SCNetworkServiceRef service = (__bridge SCNetworkServiceRef)serviceObj;
        if (!SCNetworkServiceGetEnabled(service)) {
            continue;
        }
        SCNetworkProtocolRef proto = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies);
        if (!proto) {
            continue;
        }
        [entries addObject:@{@"service": serviceObj, @"proto": CFBridgingRelease(proto)}];
    }
    return entries;
}

- (NSString *)currentPrimaryServiceID {
    id storeObj = CFBridgingRelease(SCDynamicStoreCreate(NULL, (__bridge CFStringRef)self.appTitle, NULL, NULL));
    if (!storeObj) {
        return nil;
    }
    for (NSString *key in @[@"State:/Network/Global/IPv4", @"State:/Network/Global/IPv6"]) {
        id stateObj = CFBridgingRelease(SCDynamicStoreCopyValue((__bridge SCDynamicStoreRef)storeObj, (__bridge CFStringRef)key));
        if (![stateObj isKindOfClass:NSDictionary.class]) {
            continue;
        }
        NSString *serviceID = [stateObj[@"PrimaryService"] description];
        if (serviceID.length) {
            return serviceID;
        }
    }
    return nil;
}

- (NSString *)proxyModeFromConfig:(NSDictionary *)config {
    if ([self config:config enabled:kSCPropNetProxiesProxyAutoConfigEnable]) {
        return @"pac";
    }
    if ([self config:config enabled:kSCPropNetProxiesHTTPEnable] || [self config:config enabled:kSCPropNetProxiesHTTPSEnable]) {
        return @"http";
    }
    return @"off";
}

- (BOOL)config:(NSDictionary *)config enabled:(CFStringRef)key {
    id value = config[(__bridge NSString *)key];
    if (!value) {
        return NO;
    }
    if ([value isKindOfClass:NSNumber.class]) {
        return [value intValue] != 0;
    }
    NSString *string = [Trim([value description]) lowercaseString];
    return [@[@"1", @"true", @"yes", @"on"] containsObject:string];
}

- (NSMutableDictionary *)proxyConfigFromProtocol:(SCNetworkProtocolRef)proto {
    CFDictionaryRef raw = SCNetworkProtocolGetConfiguration(proto);
    NSDictionary *rawDict = raw ? (__bridge NSDictionary *)raw : @{};
    NSMutableDictionary *config = [NSMutableDictionary dictionary];
    for (id key in rawDict) {
        config[[key description]] = rawDict[key];
    }
    return config;
}

- (NSArray<NSString *> *)setSystemProxy:(NSString *)mode settings:(ProxySettings *)settings {
    id prefsObj = CFBridgingRelease([self authorizedPreferences]);
    SCPreferencesRef prefs = (__bridge SCPreferencesRef)prefsObj;
    NSMutableArray<NSString *> *changed = [NSMutableArray array];

    for (NSDictionary *entry in [self enabledProxyProtocols:prefs]) {
        SCNetworkServiceRef service = (__bridge SCNetworkServiceRef)entry[@"service"];
        SCNetworkProtocolRef proto = (__bridge SCNetworkProtocolRef)entry[@"proto"];
        NSMutableDictionary *config = [self proxyConfigFromProtocol:proto];
        [self applyProxyConfig:config mode:mode settings:settings];

        if (!SCNetworkProtocolSetConfiguration(proto, (__bridge CFDictionaryRef)config)) {
            @throw [self scError:@"set proxy protocol"];
        }
        [changed addObject:[self serviceName:service]];
    }

    if (changed.count == 0) {
        @throw [RuntimeError errorWithReason:@"no enabled network services found"];
    }
    if (!SCPreferencesCommitChanges(prefs)) {
        @throw [self scError:@"commit proxy settings"];
    }
    if (!SCPreferencesApplyChanges(prefs)) {
        @throw [self scError:@"apply proxy settings"];
    }
    return changed;
}

- (NSString *)serviceName:(SCNetworkServiceRef)service {
    CFStringRef name = SCNetworkServiceGetName(service);
    return name ? (__bridge NSString *)name : @"Unknown";
}

- (void)applyProxyConfig:(NSMutableDictionary *)config mode:(NSString *)mode settings:(ProxySettings *)settings {
    config[(__bridge NSString *)kSCPropNetProxiesHTTPEnable] = [mode isEqualToString:@"http"] ? @1 : @0;
    config[(__bridge NSString *)kSCPropNetProxiesHTTPSEnable] = [mode isEqualToString:@"http"] ? @1 : @0;
    config[(__bridge NSString *)kSCPropNetProxiesProxyAutoConfigEnable] = [mode isEqualToString:@"pac"] ? @1 : @0;

    if ([mode isEqualToString:@"http"]) {
        if (!settings) {
            @throw [RuntimeError errorWithReason:@"missing proxy settings"];
        }
        config[(__bridge NSString *)kSCPropNetProxiesHTTPProxy] = settings.host;
        config[(__bridge NSString *)kSCPropNetProxiesHTTPPort] = @(settings.port.integerValue);
        config[(__bridge NSString *)kSCPropNetProxiesHTTPSProxy] = settings.host;
        config[(__bridge NSString *)kSCPropNetProxiesHTTPSPort] = @(settings.port.integerValue);
    } else if ([mode isEqualToString:@"pac"]) {
        if (!settings.pacURL) {
            @throw [RuntimeError errorWithReason:@"missing proxy settings"];
        }
        config[(__bridge NSString *)kSCPropNetProxiesProxyAutoConfigURLString] = settings.pacURL;
    }
}

- (SCPreferencesRef)authorizedPreferences {
    if (!self.authorization) {
        AuthorizationRef auth = NULL;
        AuthorizationFlags flags = kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights | kAuthorizationFlagPreAuthorize;
        OSStatus status = AuthorizationCreate(NULL, NULL, flags, &auth);
        if (status != errAuthorizationSuccess || !auth) {
            @throw [self authorizationError:status];
        }
        self.authorization = auth;
    }

    SCPreferencesRef prefs = SCPreferencesCreateWithAuthorization(NULL, (__bridge CFStringRef)self.appTitle, NULL, self.authorization);
    if (!prefs) {
        @throw [self scError:@"open network preferences"];
    }
    return prefs;
}

- (NSException *)authorizationError:(OSStatus)status {
    CFStringRef message = SecCopyErrorMessageString(status, NULL);
    if (message) {
        NSString *reason = CFBridgingRelease(message);
        return [RuntimeError errorWithReason:reason];
    }
    return [RuntimeError errorWithReason:[NSString stringWithFormat:@"authorization failed: %d", (int)status]];
}

- (NSException *)scError:(NSString *)context {
    const char *message = SCErrorString(SCError());
    NSString *reason = message ? [NSString stringWithUTF8String:message] : @"unknown error";
    return [RuntimeError errorWithReason:[NSString stringWithFormat:@"%@: %@", context, reason]];
}
@end

int main(int argc, const char *argv[]) {
    DetachFromTerminalIfNeeded(argc, argv);
    @autoreleasepool {
        NSApplication *app = NSApplication.sharedApplication;
        AppDelegate *delegate = [AppDelegate new];
        app.delegate = delegate;
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
        [app run];
    }
    return 0;
}
