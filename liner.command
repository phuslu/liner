(/usr/bin/python3 -x "$0" >/dev/null 2>&1 &); exit
#!/usr/bin/python3
#
# Liner macOS 状态栏托盘程序 —— Python 3.9 单文件脚本版
#
# 用法：
#   ./liner.command
#
# 同目录下需有同名的可执行二进制，本脚本作为它的 GUI 外壳。
#
# 依赖：macOS 自带 /usr/bin/python3，以及 PyObjC 的 Cocoa/
# SystemConfiguration/Security 桥接。部分 macOS/Xcode CLT 环境不预装
# PyObjC；若导入失败，用下面命令安装到当前用户环境：
#   /usr/bin/python3 -m pip install --user \
#     'pyobjc-core==11.1' \
#     'pyobjc-framework-Cocoa==11.1' \
#     'pyobjc-framework-SystemConfiguration==11.1' \
#     'pyobjc-framework-Security==11.1'
# 不要安装名为 `AppKit` 的 PyPI 包；这里需要的是 PyObjC 提供的
# `from AppKit import ...` 模块。

from __future__ import annotations

import os
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

CHILD_BIN = os.path.splitext(os.path.basename(__file__))[0]
APP_TITLE = CHILD_BIN.title()
LOG_WINDOW_TITLE = f"{APP_TITLE} Activity Log"

CONSOLE_MAX_LENGTH = 2_000_000
CONSOLE_TRIM_EXTRA = 100_000
CHILD_STOP_TIMEOUT = 5.0

if os.path.isfile('pyobjc.zip') and not os.path.isdir('pyobjc'):
    try:
        import objc, SystemConfiguration
    except ImportError:
        with zipfile.ZipFile('pyobjc.zip', 'r') as zf:
            zf.extractall('pyobjc')
sys.path.append('pyobjc')

try:
    import objc
    from AppKit import *  # noqa: F401,F403
    from Foundation import *  # noqa: F401,F403
    from Security import *  # noqa: F401,F403
    from SystemConfiguration import *  # noqa: F401,F403
except ImportError as error:  # pragma: no cover - only meaningful on non-macOS hosts.
    sys.stderr.write(
        f"{CHILD_BIN}.command requires macOS /usr/bin/python3 with PyObjC bindings.\n"
        f"Current Python: {sys.executable}\n"
        "If you installed with /usr/bin/python3 -m pip, run this script with:\n"
        f"  /usr/bin/python3 {CHILD_BIN}.command\n"
        "For Apple's Python 3.9, install:\n"
        "  /usr/bin/python3 -m pip install --user "
        "'pyobjc-core==11.1' 'pyobjc-framework-Cocoa==11.1' "
        "'pyobjc-framework-SystemConfiguration==11.1' "
        "'pyobjc-framework-Security==11.1'\n"
        "Do not install the unrelated PyPI package named AppKit.\n"
        f"Import error: {error}\n"
    )
    sys.exit(1)


def appkit_constant(names: Iterable[str], default: Any = None) -> Any:
    for name in names:
        if name in globals():
            return globals()[name]
    return default


WINDOW_STYLE_MASK = (
    appkit_constant(("NSWindowStyleMaskTitled", "NSTitledWindowMask"), 1 << 0)
    | appkit_constant(("NSWindowStyleMaskClosable", "NSClosableWindowMask"), 1 << 1)
    | appkit_constant(("NSWindowStyleMaskResizable", "NSResizableWindowMask"), 1 << 3)
)
STATUS_ITEM_SQUARE_LENGTH = appkit_constant(("NSSquareStatusItemLength",), -2.0)
ACTIVATION_POLICY_ACCESSORY = appkit_constant(
    ("NSApplicationActivationPolicyAccessory",), 1
)
LINE_CAP_ROUND = appkit_constant(
    ("NSLineCapStyleRound", "NSRoundLineCapStyle"), 1
)
LINE_JOIN_ROUND = appkit_constant(
    ("NSLineJoinStyleRound", "NSRoundLineJoinStyle"), 1
)
MENU_STATE_ON = appkit_constant(("NSControlStateValueOn", "NSOnState"), 1)
MENU_STATE_OFF = appkit_constant(("NSControlStateValueOff", "NSOffState"), 0)
ALERT_FIRST_BUTTON_RETURN = appkit_constant(("NSAlertFirstButtonReturn",), 1000)
CONSOLE_BORDER_WIDTH = 3.0
IGNORED_PROFILE_FILES = {"example.yaml"}


def rgb(red: float, green: float, blue: float):
    return NSColor.colorWithDeviceRed_green_blue_alpha_(red, green, blue, 1.0)


def nscolor(selector: str, fallback):
    method = getattr(NSColor, selector, None)
    if method is None:
        return fallback
    try:
        return method()
    except Exception:
        return fallback


CONSOLE_BORDER_COLOR = nscolor("windowFrameColor", rgb(0.2422, 0.2422, 0.25))

ANSI_COLORS = [
    NSColor.whiteColor(),
    rgb(0.7578, 0.2109, 0.1289),
    rgb(0.1445, 0.7344, 0.1406),
    rgb(0.6758, 0.6758, 0.1523),
    rgb(0.2852, 0.1797, 0.8789),
    rgb(0.8242, 0.2188, 0.8242),
    rgb(0.1992, 0.7305, 0.7813),
    rgb(0.7930, 0.7969, 0.8008),
]


class ConsoleBorderView(NSView):
    def isOpaque(self):
        return True

    def drawRect_(self, dirty_rect):
        bounds = self.bounds()
        x = bounds.origin.x
        y = bounds.origin.y
        width = bounds.size.width
        height = bounds.size.height

        NSColor.blackColor().setFill()
        NSRectFill(bounds)

        border_width = min(CONSOLE_BORDER_WIDTH, width / 2.0, height / 2.0)
        if border_width <= 0:
            return

        CONSOLE_BORDER_COLOR.setFill()
        NSRectFill(NSMakeRect(x, y, width, border_width))
        NSRectFill(NSMakeRect(x, y + height - border_width, width, border_width))
        NSRectFill(NSMakeRect(x, y, border_width, height))
        NSRectFill(NSMakeRect(x + width - border_width, y, border_width, height))


@dataclass
class ProxySettings:
    host: str
    port: str
    pac_url: Optional[str] = None

    @property
    def address(self) -> str:
        return f"{self.url_host(self.host)}:{self.port}"

    @staticmethod
    def url_host(host: str) -> str:
        if ":" in host and not host.startswith("[") and not host.endswith("]"):
            return f"[{host}]"
        return host


class AppDelegate(NSObject):
    def init(self):
        self = objc.super(AppDelegate, self).init()
        if self is None:
            return None

        self.status_item = None
        self.console_window = None
        self.console_border_view = None
        self.console_view = None
        self.child_process = None
        self.authorization = None
        self.expected_termination_pids = set()
        self.current_color = ANSI_COLORS[0]
        self.event_queue: "queue.Queue[Tuple[Any, ...]]" = queue.Queue()
        self.event_timer = None
        self.terminating_from_signal = False
        self.proxy_menu = None
        self.proxy_disable_item = None
        self.proxy_pac_item = None
        self.proxy_manual_item = None
        self.profile_menu = None
        self.profile_items: Dict[str, Any] = {}
        self.profiles: List[str] = []
        self.selected_profile: Optional[str] = None
        self.preferences_item = None
        self.start_stop_item = None
        self.sudo_askpass_path: Optional[str] = None

        self.console_font = (
            NSFont.fontWithName_size_("Monaco", 12.0)
            or NSFont.userFixedPitchFontOfSize_(12.0)
        )
        self.work_dir = self.resolve_work_dir()
        self.load_profiles()
        return self

    # ----- App lifecycle -----

    def applicationDidFinishLaunching_(self, notification):
        os.chdir(self.work_dir)

        self.setup_status_item()
        self.setup_console_window()
        self.setup_event_timer()
        self.show_startup_prompt()
        self.showConsole_(None)
        self.install_signal_handlers()

    def applicationWillTerminate_(self, notification):
        self.stop_child()
        self.cleanup_sudo_askpass()

    def windowShouldClose_(self, sender):
        sender.orderOut_(None)
        return False

    @staticmethod
    def resolve_work_dir() -> str:
        script = Path(sys.argv[0])
        if not script.is_absolute():
            script = Path.cwd() / script
        return str(script.resolve().parent)

    def show_startup_prompt(self):
        self.append_to_console(f"Working directory: {self.work_dir}\n", ANSI_COLORS[7])
        if not self.profiles:
            self.append_to_console(
                "No Liner profiles found. Add a .yaml file starting with `global:`.\n",
                ANSI_COLORS[3],
            )
            return

        if self.selected_profile is not None:
            self.append_to_console(
                f"Selected profile: {self.selected_profile}\n", ANSI_COLORS[2]
            )
            self.append_to_console(
                "Choose Start from the status menu to run liner.\n", ANSI_COLORS[3]
            )
            return

        self.append_to_console(
            "Select a profile from Profiles, then choose Start to run liner.\n",
            ANSI_COLORS[3],
        )

    # ----- 状态栏 -----

    def make_tray_icon(self):
        image = NSImage.alloc().initWithSize_(NSMakeSize(18.0, 18.0))
        image.lockFocus()
        try:
            NSColor.blackColor().set()

            for points in (
                ((4.5, 12.35), (9.0, 12.35), (13.5, 9.0)),
                ((4.5, 5.65), (9.0, 5.65), (13.5, 9.0)),
            ):
                path = NSBezierPath.bezierPath()
                path.moveToPoint_(NSMakePoint(*points[0]))
                path.lineToPoint_(NSMakePoint(*points[1]))
                path.lineToPoint_(NSMakePoint(*points[2]))
                path.setLineWidth_(2.1)
                path.setLineCapStyle_(LINE_CAP_ROUND)
                path.setLineJoinStyle_(LINE_JOIN_ROUND)
                path.stroke()

            for x, y in ((4.5, 12.35), (13.5, 9.0), (4.5, 5.65)):
                node = NSBezierPath.bezierPathWithOvalInRect_(
                    NSMakeRect(x - 2.35, y - 2.35, 4.7, 4.7)
                )
                node.fill()
        finally:
            image.unlockFocus()

        image.setTemplate_(True)
        return image

    def setup_status_item(self):
        self.status_item = NSStatusBar.systemStatusBar().statusItemWithLength_(
            STATUS_ITEM_SQUARE_LENGTH
        )

        button = self.status_item.button()
        if button is not None:
            button.setImage_(self.make_tray_icon())
            button.setToolTip_(APP_TITLE)

        menu = NSMenu.alloc().init()
        menu.setAutoenablesItems_(False)
        menu.addItem_(self.make_item("Activity Log", "showConsole:", "macwindow"))
        menu.addItem_(NSMenuItem.separatorItem())

        profile_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Profiles", None, ""
        )
        self.set_item_symbol(profile_item, "square.stack", "Profiles")
        self.profile_menu = NSMenu.alloc().init()
        profile_item.setSubmenu_(self.profile_menu)
        self.rebuild_profile_menu()
        menu.addItem_(profile_item)

        proxy_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Network", None, ""
        )
        self.set_item_symbol(proxy_item, "network", "Network")
        submenu = NSMenu.alloc().init()
        submenu.setAutoenablesItems_(False)
        submenu.setDelegate_(self)
        self.proxy_menu = submenu

        disable_item = self.make_item("Disable", "setProxyOff:")
        self.proxy_disable_item = disable_item
        submenu.addItem_(disable_item)

        pac_item = self.make_item("Auto Configuration (PAC)", "setProxyPac:")
        self.proxy_pac_item = pac_item
        submenu.addItem_(pac_item)

        manual_item = self.make_item("Manual (HTTP/HTTPS)", "setProxyHttp:")
        self.proxy_manual_item = manual_item
        submenu.addItem_(manual_item)

        proxy_item.setSubmenu_(submenu)
        menu.addItem_(proxy_item)
        menu.addItem_(NSMenuItem.separatorItem())

        self.preferences_item = self.make_item(
            "Preferences…", "editConfig:", "slider.horizontal.3"
        )
        menu.addItem_(self.preferences_item)
        menu.addItem_(NSMenuItem.separatorItem())

        self.start_stop_item = self.make_item("Start", "startChild:", "play.circle")
        menu.addItem_(self.start_stop_item)
        menu.addItem_(self.make_item("Restart", "reload:", "arrow.clockwise"))
        menu.addItem_(NSMenuItem.separatorItem())
        menu.addItem_(self.make_item(f"Quit {APP_TITLE}", "quit:", "xmark.circle"))

        self.status_item.setMenu_(menu)
        self.update_proxy_menu_state()
        self.update_profile_menu_state()
        self.update_preferences_menu_state()
        self.update_process_menu_state()

    def make_item(self, title: str, action: str, symbol_name: Optional[str] = None):
        item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(title, action, "")
        item.setTarget_(self)
        if symbol_name is not None:
            self.set_item_symbol(item, symbol_name, title)
        return item

    def set_item_symbol(self, item, symbol_name: str, description: str):
        try:
            item.setImage_(self.symbol_image(symbol_name, description))
        except Exception:
            pass

    @staticmethod
    def symbol_image(symbol_name: str, description: str):
        method = getattr(
            NSImage, "imageWithSystemSymbolName_accessibilityDescription_", None
        )
        if method is None:
            return None
        try:
            image = method(symbol_name, description)
        except Exception:
            return None
        if image is not None:
            image.setTemplate_(True)
        return image

    def menuNeedsUpdate_(self, menu):
        if menu == self.proxy_menu:
            self.update_proxy_menu_state()

    def load_profiles(self):
        self.profiles = self.scan_profiles()
        if len(self.profiles) == 1:
            self.selected_profile = self.profiles[0]
        elif self.selected_profile not in self.profiles:
            self.selected_profile = None

    def scan_profiles(self) -> List[str]:
        try:
            entries = sorted(os.listdir(self.work_dir))
        except OSError:
            return []
        return [
            entry
            for entry in entries
            if entry.endswith(".yaml")
            and entry not in IGNORED_PROFILE_FILES
            and os.path.isfile(os.path.join(self.work_dir, entry))
            and self.is_liner_profile_file(os.path.join(self.work_dir, entry))
        ]

    @staticmethod
    def is_liner_profile_file(path: str) -> bool:
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    return line.startswith("global:")
        except OSError:
            pass
        return False

    def rebuild_profile_menu(self):
        if self.profile_menu is None:
            return

        while self.profile_menu.numberOfItems() > 0:
            self.profile_menu.removeItemAtIndex_(0)

        self.profile_items = {}
        if not self.profiles:
            item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "No Liner Profiles", None, ""
            )
            item.setEnabled_(False)
            self.profile_menu.addItem_(item)
            return

        for profile in self.profiles:
            item = self.make_item(profile, "selectProfile:")
            item.setRepresentedObject_(profile)
            self.profile_items[profile] = item
            self.profile_menu.addItem_(item)
        self.update_profile_menu_state()

    def update_profile_menu_state(self):
        for profile, item in self.profile_items.items():
            item.setState_(
                MENU_STATE_ON if profile == self.selected_profile else MENU_STATE_OFF
            )
        self.update_preferences_menu_state()

    def update_preferences_menu_state(self):
        if self.preferences_item is None:
            return
        self.preferences_item.setEnabled_(self.selected_profile in self.profile_items)

    def is_child_running(self) -> bool:
        process = self.child_process
        return process is not None and process.poll() is None

    def child_command(self) -> Optional[Tuple[List[str], str]]:
        bin_path = os.path.join(self.work_dir, CHILD_BIN)
        if os.path.exists(bin_path):
            if os.access(bin_path, os.X_OK):
                return [bin_path], CHILD_BIN
            self.append_to_console(f"Cannot execute: {bin_path}\n", ANSI_COLORS[1])
            return None

        so_path = os.path.join(self.work_dir, CHILD_BIN + ".so")
        if sys.platform == "darwin" and os.path.isfile(so_path):
            command = ["/usr/bin/python3", "-c", "__import__('liner').liner()"]
            return command, "/usr/bin/python3 -c \"__import__('liner').liner()\""

        self.append_to_console(f"Cannot find executable: {bin_path}\n", ANSI_COLORS[1])
        return None

    def update_process_menu_state(self):
        if self.start_stop_item is None:
            return
        if self.is_child_running():
            self.start_stop_item.setTitle_("Stop")
            self.start_stop_item.setAction_("stopChild:")
            self.set_item_symbol(self.start_stop_item, "stop.circle", "Stop")
        else:
            self.start_stop_item.setTitle_("Start")
            self.start_stop_item.setAction_("startChild:")
            self.set_item_symbol(self.start_stop_item, "play.circle", "Start")
        self.start_stop_item.setTarget_(self)

    # ----- 控制台窗口 -----

    def setup_console_window(self):
        frame = NSMakeRect(0.0, 0.0, 800.0, 600.0)
        self.console_window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            frame, WINDOW_STYLE_MASK, NSBackingStoreBuffered, False
        )
        self.console_window.setTitle_(LOG_WINDOW_TITLE)
        self.console_window.setDelegate_(self)
        self.console_window.setReleasedWhenClosed_(False)

        self.console_border_view = ConsoleBorderView.alloc().initWithFrame_(frame)
        self.console_border_view.setAutoresizingMask_(
            NSViewWidthSizable | NSViewHeightSizable
        )

        scroll_frame = NSMakeRect(
            CONSOLE_BORDER_WIDTH,
            CONSOLE_BORDER_WIDTH,
            frame.size.width - CONSOLE_BORDER_WIDTH * 2.0,
            frame.size.height - CONSOLE_BORDER_WIDTH * 2.0,
        )
        scroll = NSScrollView.alloc().initWithFrame_(scroll_frame)
        scroll.setBorderType_(NSNoBorder)
        scroll.setHasVerticalScroller_(True)
        scroll.setHasHorizontalScroller_(False)
        scroll.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)

        text_frame = NSMakeRect(
            0.0, 0.0, scroll_frame.size.width, scroll_frame.size.height
        )
        self.console_view = NSTextView.alloc().initWithFrame_(text_frame)
        self.console_view.setBackgroundColor_(NSColor.blackColor())
        self.console_view.setRichText_(True)
        self.console_view.setEditable_(False)
        self.console_view.setVerticallyResizable_(True)
        self.console_view.setHorizontallyResizable_(False)
        self.console_view.setAutoresizingMask_(NSViewWidthSizable)
        self.console_view.setFont_(self.console_font)

        scroll.setDocumentView_(self.console_view)
        self.console_border_view.addSubview_(scroll)
        self.console_window.contentView().addSubview_(self.console_border_view)

    def setup_event_timer(self):
        self.event_timer = NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
            0.05, self, "drainEvents:", None, True
        )

    def drainEvents_(self, timer):
        for _ in range(1000):
            try:
                event = self.event_queue.get_nowait()
            except queue.Empty:
                break

            kind = event[0]
            if kind == "output":
                self.handle_incoming(event[1])
            elif kind == "terminated":
                _, process, return_code = event
                self.child_did_terminate(process, return_code)
            elif kind == "signal":
                self.terminate_from_signal(event[1])

    # ----- 配置 / 系统代理推断 -----

    def inspect_proxy_config(self) -> Tuple[bool, Optional[ProxySettings]]:
        config_file = self.selected_profile
        if not config_file:
            return False, None

        has_http = False
        settings = None
        pac_location = None
        config_path = os.path.join(self.work_dir, config_file)
        for path in self.config_data_paths(config_path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except OSError:
                continue
            found_http, listen = self.first_http_listen(content)
            has_http = has_http or found_http
            if settings is None and listen:
                settings = self.proxy_settings_from_listen(listen)
            if pac_location is None:
                pac_location = self.first_http_pac_location(content)
        if settings is not None and pac_location is not None:
            settings.pac_url = self.pac_url_for(
                settings.host, settings.port, pac_location
            )
        return has_http, settings

    def profile_has_tun_section(self, config_file: str) -> bool:
        config_path = os.path.join(self.work_dir, config_file)
        for path in self.config_data_paths(config_path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except OSError:
                continue
            if self.yaml_has_top_level_key(content, "tun"):
                return True
        return False

    def yaml_has_top_level_key(self, yaml_text: str, key: str) -> bool:
        key_prefix = key + ":"
        for raw_line in yaml_text.splitlines():
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            if self.line_indent(raw_line) != 0:
                continue
            trimmed = self.strip_yaml_comment(raw_line).strip()
            if trimmed == key_prefix or trimmed.startswith(key_prefix + " "):
                return True
        return False

    def proxy_settings_unavailable_tooltip(self) -> str:
        if not self.selected_profile:
            return "No profile selected"
        has_http, _ = self.inspect_proxy_config()
        if not has_http:
            return "No http: section in selected profile"
        return "No HTTP listen address found"

    def proxy_pac_unavailable_tooltip(self) -> str:
        return "No .pac web location in selected profile's http: section"

    @staticmethod
    def config_data_paths(config_path: str) -> List[str]:
        base, _ = os.path.splitext(config_path)
        overlay_dir = base + ".d"
        overlays: List[str] = []
        try:
            entries = sorted(os.listdir(overlay_dir))
        except OSError:
            entries = []

        for entry in entries:
            if entry.endswith(".yaml"):
                overlays.append(os.path.join(overlay_dir, entry))
        return [config_path] + overlays

    def first_http_listen(self, yaml_text: str) -> Tuple[bool, Optional[str]]:
        in_http = False
        in_listen_block = False

        for raw_line in yaml_text.splitlines():
            trimmed = raw_line.strip()
            if not trimmed or trimmed.startswith("#"):
                continue

            if not in_http:
                if trimmed == "http:" or trimmed.startswith("http: "):
                    in_http = True
                continue

            if raw_line and not raw_line[0].isspace() and not trimmed.startswith("- "):
                return True, None

            if in_listen_block:
                if trimmed.startswith("- "):
                    value = self.clean_yaml_scalar(trimmed[2:])
                    if value:
                        return True, value
                if not trimmed.startswith("#"):
                    in_listen_block = False

            candidate = trimmed[2:].strip() if trimmed.startswith("- ") else trimmed
            if not candidate.startswith("listen:"):
                continue

            raw_value = candidate[len("listen:") :].strip()
            if not raw_value:
                in_listen_block = True
            else:
                return True, self.first_listen_scalar(raw_value)

        return in_http, None

    def first_http_pac_location(self, yaml_text: str) -> Optional[str]:
        in_http = False
        in_web = False
        web_indent = 0
        web_item_indent: Optional[int] = None
        web_location: Optional[str] = None
        web_file: Optional[str] = None
        web_has_index = False

        def flush_web_item() -> Optional[str]:
            if not web_location or not web_has_index:
                return None
            if self.is_pac_location(web_location) or (
                web_file is not None and self.is_pac_location(web_file)
            ):
                return self.normalize_web_location(web_location)
            return None

        for raw_line in yaml_text.splitlines():
            trimmed = raw_line.strip()
            if not trimmed or trimmed.startswith("#"):
                continue

            indent = self.line_indent(raw_line)
            if not in_http:
                if trimmed == "http:" or trimmed.startswith("http: "):
                    in_http = True
                continue

            if raw_line and not raw_line[0].isspace() and not trimmed.startswith("- "):
                return flush_web_item()

            if in_web and indent <= web_indent:
                location = flush_web_item()
                if location:
                    return location
                in_web = False
                web_item_indent = None
                web_location = None
                web_file = None
                web_has_index = False

            candidate = trimmed[2:].strip() if trimmed.startswith("- ") else trimmed
            if in_web:
                if trimmed.startswith("- ") and indent > web_indent:
                    if web_item_indent is None:
                        web_item_indent = indent
                    if indent == web_item_indent:
                        location = flush_web_item()
                        if location:
                            return location
                        web_location = None
                        web_file = None
                        web_has_index = False
                        candidate = trimmed[2:].strip()

                if candidate.startswith("location:"):
                    web_location = self.clean_yaml_scalar(
                        candidate[len("location:") :].strip()
                    )
                elif candidate.startswith("index:"):
                    web_has_index = True
                elif candidate.startswith("file:"):
                    web_file = self.clean_yaml_scalar(candidate[len("file:") :].strip())

                location = flush_web_item()
                if location:
                    return location
                continue

            if candidate.startswith("web:"):
                in_web = True
                web_indent = indent
                web_item_indent = None
                web_location = None
                web_file = None
                web_has_index = False

        return flush_web_item() if in_http else None

    @staticmethod
    def line_indent(raw_line: str) -> int:
        return len(raw_line) - len(raw_line.lstrip())

    @staticmethod
    def normalize_web_location(location: str) -> str:
        if not location.startswith("/"):
            return "/" + location
        return location

    @staticmethod
    def is_pac_location(location: str) -> bool:
        path = location.split("?", 1)[0].lower()
        return path.endswith(".pac")

    @staticmethod
    def pac_url_for(host: str, port: str, location: str) -> str:
        path = AppDelegate.normalize_web_location(location)
        return f"http://{ProxySettings.url_host(host)}:{port}{path}"

    def first_listen_scalar(self, raw: str) -> Optional[str]:
        value = self.strip_yaml_comment(raw)
        if value.startswith("[") and value.endswith("]"):
            value = value.strip("[]")
            value = value.split(",", 1)[0] if value else ""
        return self.clean_yaml_scalar(value)

    def clean_yaml_scalar(self, raw: str) -> Optional[str]:
        value = self.strip_yaml_comment(raw)
        if not value or value in ("|", ">"):
            return None
        return self.strip_matching_quotes(value).strip()

    @staticmethod
    def strip_yaml_comment(raw: str) -> str:
        return raw.split("#", 1)[0].strip()

    @staticmethod
    def strip_matching_quotes(value: str) -> str:
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in ("'", '"')
        ):
            return value[1:-1]
        return value

    def proxy_settings_from_listen(self, raw_listen: str) -> Optional[ProxySettings]:
        listen = raw_listen.strip()
        if "://" in listen:
            listen = listen.split("://", 1)[1]
        if "/" in listen:
            listen = listen.split("/", 1)[0]
        if "?" in listen:
            listen = listen.split("?", 1)[0]

        host = ""
        port = ""
        if listen.startswith("[") and "]" in listen:
            close = listen.find("]")
            host = listen[1:close]
            rest = listen[close + 1 :]
            if not rest.startswith(":"):
                return None
            port = rest[1:]
        elif ":" in listen:
            host, port = listen.rsplit(":", 1)
        elif listen.isdigit():
            host = ""
            port = listen
        else:
            return None

        try:
            port_number = int(port)
        except ValueError:
            return None
        if not 1 <= port_number <= 65535:
            return None

        normalized_host = self.proxy_host_for_listen_host(host)
        return ProxySettings(normalized_host, str(port_number))

    @staticmethod
    def proxy_host_for_listen_host(host: str) -> str:
        trimmed = host.strip()
        if trimmed in ("", "*", "0.0.0.0", "::", "::0"):
            return "127.0.0.1"
        return trimmed

    # ----- 子进程 -----

    def start_child(self) -> bool:
        self.append_to_console(f"Working directory: {self.work_dir}\n", ANSI_COLORS[7])

        if self.child_process is not None and self.child_process.poll() is None:
            self.append_to_console(f"{CHILD_BIN} is already running.\n", ANSI_COLORS[3])
            self.update_process_menu_state()
            self.update_proxy_menu_state()
            return True

        child_command = self.child_command()
        if child_command is None:
            self.update_process_menu_state()
            return False
        child_args, child_display = child_command

        config_file = self.selected_profile
        if not config_file:
            self.append_to_console(
                "No profile selected. Choose one from Profiles in the status menu.\n",
                ANSI_COLORS[1],
            )
            self.update_process_menu_state()
            return False

        config_path = os.path.join(self.work_dir, config_file)
        if not os.path.exists(config_path):
            self.append_to_console(f"Config file not found: {config_path}\n", ANSI_COLORS[1])
            self.update_process_menu_state()
            return False

        environment = dict(os.environ)
        environment["LINER_LOG_TO_STDERR"] = "1"

        requires_admin = self.profile_has_tun_section(config_file)
        if requires_admin and not self.sudo_credentials_available(environment):
            if not self.confirm_tun_admin():
                self.append_to_console("Start canceled.\n", ANSI_COLORS[3])
                self.update_process_menu_state()
                return False

            self.append_to_console("Requesting administrator authorization for TUN.\n", ANSI_COLORS[3])
            ok, message = self.authorize_sudo(environment)
            if not ok:
                if message:
                    self.append_to_console(f"Administrator authorization failed: {message}\n", ANSI_COLORS[1])
                else:
                    self.append_to_console("Administrator authorization failed.\n", ANSI_COLORS[1])
                self.update_process_menu_state()
                return False

        if requires_admin:
            self.append_to_console(
                f"Starting with sudo: {child_display} {config_file}\n", ANSI_COLORS[2]
            )
        else:
            self.append_to_console(f"Starting: {child_display} {config_file}\n", ANSI_COLORS[2])

        try:
            args = child_args + [config_file]
            if requires_admin:
                args = [
                    "/usr/bin/sudo",
                    "-n",
                    "--",
                    "/usr/bin/env",
                    "LINER_LOG_TO_STDERR=1",
                    *child_args,
                    config_file,
                ]
            process = subprocess.Popen(
                args,
                cwd=self.work_dir,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
        except Exception as exc:
            self.append_to_console(f"Failed to start {CHILD_BIN}: {exc}\n", ANSI_COLORS[1])
            self.update_process_menu_state()
            return False

        self.child_process = process
        self.start_reading(process.stdout)
        self.start_reading(process.stderr)
        self.start_watching(process)
        self.update_process_menu_state()
        self.update_proxy_menu_state()
        return True

    def sudo_credentials_available(self, environment: Dict[str, str]) -> bool:
        try:
            result = subprocess.run(
                ["/usr/bin/sudo", "-n", "true"],
                cwd=self.work_dir,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            return False
        return result.returncode == 0

    def confirm_tun_admin(self) -> bool:
        alert = NSAlert.alloc().init()
        alert.setMessageText_("TUN 需要管理员权限")
        alert.setInformativeText_(
            "The selected profile contains a tun: section. "
            "Liner needs administrator privileges to create and configure the TUN interface."
        )
        alert.addButtonWithTitle_("Continue")
        alert.addButtonWithTitle_("Cancel")
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        return alert.runModal() == ALERT_FIRST_BUTTON_RETURN

    def authorize_sudo(self, environment: Dict[str, str]) -> Tuple[bool, str]:
        auth_environment = dict(environment)
        auth_environment["SUDO_ASKPASS"] = self.ensure_sudo_askpass()
        try:
            result = subprocess.run(
                [
                    "/usr/bin/sudo",
                    "-A",
                    "-v",
                    "-p",
                    f"{APP_TITLE} needs administrator privileges to start TUN.\nPassword: ",
                ],
                cwd=self.work_dir,
                env=auth_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as exc:
            return False, str(exc)

        if result.returncode != 0:
            return False, self.clean_process_error(result.stderr)
        if not self.sudo_credentials_available(environment):
            return False, "sudo credentials were not cached"
        return True, ""

    @staticmethod
    def clean_process_error(message: Optional[str]) -> str:
        if not message:
            return ""
        return " ".join(message.strip().split())

    def ensure_sudo_askpass(self) -> str:
        path = self.sudo_askpass_path
        if path and os.path.exists(path):
            return path

        fd, path = tempfile.mkstemp(prefix=f"{CHILD_BIN}-askpass-", suffix=".sh")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(
                    """#!/bin/sh
prompt=${1:-"Password:"}
exec /usr/bin/osascript - "$prompt" <<'APPLESCRIPT'
on run argv
    set promptText to item 1 of argv
    try
        set dialogResult to display dialog promptText default answer "" with hidden answer buttons {"OK", "Cancel"} default button "OK" with title "Liner" with icon caution
        return text returned of dialogResult
    on error number -128
        error number -128
    end try
end run
APPLESCRIPT
"""
                )
            os.chmod(path, 0o700)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(path)
            except OSError:
                pass
            raise

        self.sudo_askpass_path = path
        return path

    def cleanup_sudo_askpass(self):
        path = self.sudo_askpass_path
        self.sudo_askpass_path = None
        if not path:
            return
        try:
            os.unlink(path)
        except OSError:
            pass

    def start_reading(self, pipe):
        if pipe is None:
            return

        def reader():
            try:
                fd = pipe.fileno()
                while True:
                    data = os.read(fd, 4096)
                    if not data:
                        break
                    self.event_queue.put(
                        ("output", data.decode("utf-8", errors="replace"))
                    )
            except Exception as exc:
                self.event_queue.put(("output", f"\nlog reader error: {exc}\n"))
            finally:
                try:
                    pipe.close()
                except OSError:
                    pass

        threading.Thread(target=reader, daemon=True).start()

    def start_watching(self, process):
        def watcher():
            return_code = process.wait()
            self.event_queue.put(("terminated", process, return_code))

        threading.Thread(target=watcher, daemon=True).start()

    def install_signal_handlers(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self.queue_signal)

    def queue_signal(self, signum, frame):
        self.event_queue.put(("signal", signum))

    def terminate_from_signal(self, signum: int):
        if self.terminating_from_signal:
            return
        self.terminating_from_signal = True
        self.append_to_console(
            f"\nReceived signal {signum}, stopping {CHILD_BIN}...\n", ANSI_COLORS[3]
        )
        self.stop_child()
        NSApplication.sharedApplication().terminate_(None)

    def stop_child(self) -> bool:
        process = self.child_process
        if process is None:
            self.update_process_menu_state()
            self.update_proxy_menu_state()
            return True

        self.expected_termination_pids.add(process.pid)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=CHILD_STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.append_to_console(
                    f"{CHILD_BIN} did not exit after {int(CHILD_STOP_TIMEOUT)}s; "
                    "killing it.\n",
                    ANSI_COLORS[3],
                )
                process.kill()
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    pass

        stopped = process.poll() is not None
        if self.child_process is process and stopped:
            self.child_process = None
        self.update_process_menu_state()
        self.update_proxy_menu_state()
        return stopped

    def child_did_terminate(self, process, return_code: int):
        expected = process.pid in self.expected_termination_pids
        self.expected_termination_pids.discard(process.pid)
        if self.child_process is process:
            self.child_process = None
        self.update_process_menu_state()
        self.update_proxy_menu_state()
        if expected:
            return

        if return_code is not None and return_code < 0:
            reason = f"signal {-return_code}"
        else:
            reason = f"exit status {return_code}"

        self.append_to_console(f"\n{CHILD_BIN} exited unexpectedly: {reason}\n", ANSI_COLORS[1])
        button = self.status_item.button() if self.status_item is not None else None
        if button is not None:
            button.setToolTip_(f"{APP_TITLE} stopped: {reason}")
        self.showConsole_(None)
        self.send_notification(APP_TITLE, f"{CHILD_BIN} stopped: {reason}")

    # ----- 输出解析与渲染 -----

    def apply_ansi_codes(self, code_str: str):
        parts = code_str.split(";") if code_str else [""]
        for part in parts:
            try:
                code = int(part)
            except ValueError:
                code = 0
            if 30 <= code < 38:
                self.current_color = ANSI_COLORS[code - 30]
            elif code in (0, 39):
                self.current_color = ANSI_COLORS[0]

    def handle_incoming(self, raw: str):
        line = raw

        while True:
            esc_idx = line.find("\x1b]2;")
            if esc_idx < 0:
                break
            bell_idx = line.find("\x07", esc_idx + 4)
            if bell_idx < 0:
                break
            title = line[esc_idx + 4 : bell_idx]
            button = self.status_item.button() if self.status_item is not None else None
            if button is not None:
                button.setToolTip_(title)
            self.console_window.setTitle_(title)
            line = line[:esc_idx] + line[bell_idx + 1 :]

        idx = 0
        pending: List[str] = []
        while idx < len(line):
            if line[idx] == "\x1b" and idx + 1 < len(line) and line[idx + 1] == "[":
                code_start = idx + 2
                m_idx = line.find("m", code_start)
                if m_idx >= 0:
                    if pending:
                        self.append_to_console("".join(pending), self.current_color)
                        pending = []
                    self.apply_ansi_codes(line[code_start:m_idx])
                    idx = m_idx + 1
                    continue

            pending.append(line[idx])
            idx += 1

        if pending:
            self.append_to_console("".join(pending), self.current_color)

    def append_to_console(self, text: str, color):
        if self.console_view is None:
            return

        visible = self.console_view.visibleRect()
        bounds = self.console_view.bounds()
        need_scroll = self.rect_max_y(visible) >= self.rect_max_y(bounds) - 20.0

        attrs = {
            NSForegroundColorAttributeName: color,
            NSFontAttributeName: self.console_font,
        }
        attr = NSAttributedString.alloc().initWithString_attributes_(text, attrs)
        storage = self.console_view.textStorage()
        storage.appendAttributedString_(attr)
        self.trim_console_if_needed()

        if need_scroll:
            storage = self.console_view.textStorage()
            self.console_view.scrollRangeToVisible_(NSMakeRange(storage.length(), 0))

    @staticmethod
    def rect_max_y(rect) -> float:
        return rect.origin.y + rect.size.height

    def trim_console_if_needed(self):
        storage = self.console_view.textStorage()
        if storage is None:
            return
        overflow = storage.length() - CONSOLE_MAX_LENGTH
        if overflow <= 0:
            return

        delete_length = min(storage.length(), overflow + CONSOLE_TRIM_EXTRA)
        if delete_length < storage.length():
            ns_string = NSString.stringWithString_(storage.string())
            search_range = NSMakeRange(
                delete_length,
                min(4096, storage.length() - delete_length),
            )
            newline = ns_string.rangeOfString_options_range_("\n", 0, search_range)
            if newline.location != NSNotFound:
                delete_length = newline.location + newline.length

        storage.deleteCharactersInRange_(NSMakeRange(0, delete_length))

    # ----- 通知 -----

    @staticmethod
    def apple_script_string_literal(value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    def send_notification(self, title: str, body: str):
        script = (
            f"display notification {self.apple_script_string_literal(body)} "
            f"with title {self.apple_script_string_literal(title)} "
            'sound name "default"'
        )
        try:
            subprocess.Popen(
                ["/usr/bin/osascript", "-e", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            pass

    # ----- 菜单 actions -----

    def showConsole_(self, sender):
        self.console_window.center()
        self.console_window.makeKeyAndOrderFront_(None)
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)

    def setProxyOff_(self, sender):
        self.apply_proxy_mode("off")

    def setProxyPac_(self, sender):
        self.apply_proxy_mode("pac")

    def setProxyHttp_(self, sender):
        self.apply_proxy_mode("http")

    def selectProfile_(self, sender):
        profile = sender.representedObject()
        if not profile:
            return

        profile = str(profile)
        if profile not in self.profiles:
            self.append_to_console(f"Profile not found: {profile}\n", ANSI_COLORS[1])
            self.rebuild_profile_menu()
            return

        self.selected_profile = profile
        self.update_profile_menu_state()
        self.update_proxy_menu_state()
        self.append_to_console(f"Selected profile: {profile}\n", ANSI_COLORS[2])
        if self.is_child_running():
            self.append_to_console(
                "Restart liner to apply the selected profile.\n", ANSI_COLORS[3]
            )

    def editConfig_(self, sender):
        config_file = self.selected_profile
        if not config_file:
            self.append_to_console(
                "No profile selected. Choose one from Profiles in the status menu.\n",
                ANSI_COLORS[1],
            )
            self.showConsole_(None)
            return

        config_path = os.path.join(self.work_dir, config_file)
        if not os.path.exists(config_path):
            self.append_to_console(f"Config file not found: {config_path}\n", ANSI_COLORS[1])
            self.showConsole_(None)
            return

        try:
            subprocess.Popen(
                ["/usr/bin/open", "-e", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            self.append_to_console(f"Open config failed: {exc}\n", ANSI_COLORS[1])
            self.showConsole_(None)

    def reload_(self, sender):
        self.showConsole_(sender)
        if not self.stop_child():
            self.append_to_console(
                f"Restart aborted: {CHILD_BIN} is still running.\n", ANSI_COLORS[1]
            )
            return
        self.console_view.setString_("")
        if self.start_child():
            self.send_notification(APP_TITLE, "Restarted.")
        else:
            self.showConsole_(None)
            self.send_notification(APP_TITLE, "Restart failed. Check the activity log.")

    def startChild_(self, sender):
        self.showConsole_(sender)
        if self.start_child():
            self.send_notification(APP_TITLE, "Started.")
        else:
            self.showConsole_(None)
            self.send_notification(APP_TITLE, "Failed to start. Check the activity log.")

    def stopChild_(self, sender):
        self.showConsole_(sender)
        if self.stop_child():
            self.append_to_console(f"{CHILD_BIN} stopped.\n", ANSI_COLORS[3])
        else:
            self.append_to_console(f"Failed to stop {CHILD_BIN}.\n", ANSI_COLORS[1])

    def quit_(self, sender):
        self.stop_child()
        NSApplication.sharedApplication().terminate_(None)

    def apply_proxy_mode(self, mode: str):
        if mode == "off":
            settings = None
            mode_name = "Disable"
        else:
            if not self.is_child_running():
                self.update_proxy_menu_state()
                self.append_to_console(
                    f"System proxy mode unavailable: {CHILD_BIN} is not running.\n",
                    ANSI_COLORS[1],
                )
                self.showConsole_(None)
                return
            _, settings = self.inspect_proxy_config()
            if settings is None or (mode == "pac" and not settings.pac_url):
                self.update_proxy_menu_state()
                self.append_to_console(
                    "System proxy mode unavailable: selected profile has no usable proxy endpoint.\n",
                    ANSI_COLORS[1],
                )
                self.showConsole_(None)
                return
            if mode == "pac":
                mode_name = f"PAC {settings.pac_url}"
            else:
                mode_name = f"HTTP/HTTPS {settings.address}"

        try:
            services = self.set_system_proxy(mode, settings)
            self.update_proxy_menu_state()
            self.append_to_console(
                f"Applied System Proxy '{mode_name}' to: {', '.join(services)}\n",
                ANSI_COLORS[2],
            )
        except Exception as exc:
            self.append_to_console(f"System proxy update failed: {exc}\n", ANSI_COLORS[1])
            self.showConsole_(None)

    def update_proxy_menu_state(self):
        if not all(
            (
                self.proxy_disable_item,
                self.proxy_pac_item,
                self.proxy_manual_item,
            )
        ):
            return

        running = self.is_child_running()
        settings = None
        if running:
            _, settings = self.inspect_proxy_config()

        pac_enabled = running and settings is not None and settings.pac_url is not None
        manual_enabled = running and settings is not None
        self.proxy_pac_item.setEnabled_(pac_enabled)
        self.proxy_manual_item.setEnabled_(manual_enabled)
        if not running:
            tooltip = f"{CHILD_BIN} is not running"
            self.proxy_pac_item.setToolTip_(tooltip)
            self.proxy_manual_item.setToolTip_(tooltip)
        elif settings is None:
            tooltip = self.proxy_settings_unavailable_tooltip()
            self.proxy_pac_item.setToolTip_(tooltip)
            self.proxy_manual_item.setToolTip_(tooltip)
        else:
            self.proxy_pac_item.setToolTip_(
                settings.pac_url or self.proxy_pac_unavailable_tooltip()
            )
            self.proxy_manual_item.setToolTip_(settings.address)

        mode = None
        try:
            mode = self.current_system_proxy_mode()
        except Exception:
            pass

        self.proxy_disable_item.setState_(
            MENU_STATE_ON if mode == "off" else MENU_STATE_OFF
        )
        self.proxy_pac_item.setState_(
            MENU_STATE_ON if mode == "pac" else MENU_STATE_OFF
        )
        self.proxy_manual_item.setState_(
            MENU_STATE_ON if mode == "http" else MENU_STATE_OFF
        )

    def current_system_proxy_mode(self) -> Optional[str]:
        prefs = SCPreferencesCreate(None, APP_TITLE, None)
        if not prefs:
            raise self.sc_error("open network preferences")

        network_set = SCNetworkSetCopyCurrent(prefs)
        if not network_set:
            raise self.sc_error("read current network set")

        services = SCNetworkSetCopyServices(network_set)
        if services is None:
            raise self.sc_error("read network services")

        primary_service_id = self.current_primary_service_id()
        service_modes: List[str] = []
        for service in services:
            if not SCNetworkServiceGetEnabled(service):
                continue

            proto = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies)
            if not proto:
                continue

            config = dict(SCNetworkProtocolGetConfiguration(proto) or {})
            mode = self.proxy_mode_from_config(config)
            service_modes.append(mode)

            if primary_service_id:
                service_id = SCNetworkServiceGetServiceID(service)
                if service_id and str(service_id) == primary_service_id:
                    return mode

        if not service_modes:
            return None

        unique_modes = set(service_modes)
        if len(unique_modes) == 1:
            return service_modes[0]

        enabled_modes = {mode for mode in service_modes if mode != "off"}
        if len(enabled_modes) == 1:
            return next(iter(enabled_modes))
        return "mixed"

    @staticmethod
    def current_primary_service_id() -> Optional[str]:
        store = SCDynamicStoreCreate(None, APP_TITLE, None, None)
        if not store:
            return None

        for key in ("State:/Network/Global/IPv4", "State:/Network/Global/IPv6"):
            state = SCDynamicStoreCopyValue(store, key)
            if not state:
                continue
            service_id = dict(state).get("PrimaryService")
            if service_id:
                return str(service_id)
        return None

    @classmethod
    def proxy_mode_from_config(cls, config: Dict[Any, Any]) -> str:
        if cls.config_enabled(config, kSCPropNetProxiesProxyAutoConfigEnable):
            return "pac"
        if cls.config_enabled(config, kSCPropNetProxiesHTTPEnable) or cls.config_enabled(
            config, kSCPropNetProxiesHTTPSEnable
        ):
            return "http"
        return "off"

    @staticmethod
    def config_enabled(config: Dict[Any, Any], key) -> bool:
        value = config.get(str(key))
        if value is None:
            value = config.get(key)
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        try:
            return int(value) != 0
        except (TypeError, ValueError):
            return str(value).strip().lower() in ("1", "true", "yes", "on")

    def set_system_proxy(self, mode: str, settings: Optional[ProxySettings]) -> List[str]:
        prefs = self.authorized_preferences()
        network_set = SCNetworkSetCopyCurrent(prefs)
        if not network_set:
            raise self.sc_error("read current network set")

        services = SCNetworkSetCopyServices(network_set)
        if services is None:
            raise self.sc_error("read network services")

        changed: List[str] = []
        for service in services:
            if not SCNetworkServiceGetEnabled(service):
                continue

            proto = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies)
            if not proto:
                continue

            config = SCNetworkProtocolGetConfiguration(proto) or {}
            config = dict(config)
            self.apply_proxy_config(config, mode, settings)

            if not SCNetworkProtocolSetConfiguration(proto, config):
                raise self.sc_error("set proxy protocol")

            name = SCNetworkServiceGetName(service) or "Unknown"
            changed.append(str(name))

        if not changed:
            raise RuntimeError("no enabled network services found")
        if not SCPreferencesCommitChanges(prefs):
            raise self.sc_error("commit proxy settings")
        if not SCPreferencesApplyChanges(prefs):
            raise self.sc_error("apply proxy settings")
        return changed

    @staticmethod
    def apply_proxy_config(
        config: Dict[Any, Any], mode: str, settings: Optional[ProxySettings]
    ):
        config[str(kSCPropNetProxiesHTTPEnable)] = 1 if mode == "http" else 0
        config[str(kSCPropNetProxiesHTTPSEnable)] = 1 if mode == "http" else 0
        config[str(kSCPropNetProxiesProxyAutoConfigEnable)] = 1 if mode == "pac" else 0

        if mode == "http":
            if settings is None:
                raise RuntimeError("missing proxy settings")
            port = int(settings.port)
            config[str(kSCPropNetProxiesHTTPProxy)] = settings.host
            config[str(kSCPropNetProxiesHTTPPort)] = port
            config[str(kSCPropNetProxiesHTTPSProxy)] = settings.host
            config[str(kSCPropNetProxiesHTTPSPort)] = port
        elif mode == "pac":
            if settings is None or settings.pac_url is None:
                raise RuntimeError("missing proxy settings")
            config[str(kSCPropNetProxiesProxyAutoConfigURLString)] = settings.pac_url

    def authorized_preferences(self):
        if self.authorization is None:
            flags = (
                kAuthorizationFlagInteractionAllowed
                | kAuthorizationFlagExtendRights
                | kAuthorizationFlagPreAuthorize
            )
            try:
                result = AuthorizationCreate(None, None, flags, None)
            except TypeError:
                result = AuthorizationCreate(None, None, flags)
            if isinstance(result, tuple):
                status = result[0]
                auth = result[1] if len(result) > 1 else None
            else:
                status = result
                auth = None
            if status != errAuthorizationSuccess or auth is None:
                raise self.authorization_error(status)
            self.authorization = auth

        prefs = SCPreferencesCreateWithAuthorization(
            None, APP_TITLE, None, self.authorization
        )
        if not prefs:
            raise self.sc_error("open network preferences")
        return prefs

    @staticmethod
    def authorization_error(status) -> Exception:
        message = SecCopyErrorMessageString(status, None)
        return RuntimeError(str(message) if message else f"authorization failed: {status}")

    @staticmethod
    def sc_error(context: str) -> Exception:
        return RuntimeError(f"{context}: {SCErrorString(SCError())}")


app = NSApplication.sharedApplication()
delegate = AppDelegate.alloc().init()
app.setDelegate_(delegate)
app.setActivationPolicy_(ACTIVATION_POLICY_ACCESSORY)
app.run()
