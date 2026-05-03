#!/usr/bin/env swift
//
// Liner macOS 状态栏托盘程序 —— Swift 单文件脚本版
//
// 用法：
//   chmod +x liner-macos.command
//   ./liner-macos.command           # 命令行运行
//   双击 liner-macos.command        # Finder 中双击启动
//
// 同目录下需有 `liner` 可执行二进制，本脚本作为它的 GUI 外壳。
//
// 依赖：macOS 自带 Swift 工具链（首次会触发 Xcode CLT 安装提示，
// 一次性 `xcode-select --install` 即可，无 pip / brew 依赖）。
//

import Cocoa
import Foundation

// ============================================================
// 常量
// ============================================================

// 子进程二进制名（与本脚本同目录）
let CHILD_BIN = "liner"

// 应用显示名 / 默认窗口标题 / tooltip
let APP_TITLE = "Liner"

// ANSI 颜色 → NSColor，索引 0..7 对应 ANSI 30..37
let ansiColors: [NSColor] = [
    .white,
    NSColor(deviceRed: 0.7578, green: 0.2109, blue: 0.1289, alpha: 1.0),
    NSColor(deviceRed: 0.1445, green: 0.7344, blue: 0.1406, alpha: 1.0),
    NSColor(deviceRed: 0.6758, green: 0.6758, blue: 0.1523, alpha: 1.0),
    NSColor(deviceRed: 0.2852, green: 0.1797, blue: 0.8789, alpha: 1.0),
    NSColor(deviceRed: 0.8242, green: 0.2188, blue: 0.8242, alpha: 1.0),
    NSColor(deviceRed: 0.1992, green: 0.7305, blue: 0.7813, alpha: 1.0),
    NSColor(deviceRed: 0.7930, green: 0.7969, blue: 0.8008, alpha: 1.0),
]


// ============================================================
// AppDelegate
// ============================================================

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {

    var statusItem: NSStatusItem!
    var consoleWindow: NSWindow!
    var consoleView: NSTextView!
    var childProcess: Process?
    var pendingBuffer = Data()
    var currentColor: NSColor = ansiColors[0]
    let consoleFont = NSFont(name: "Monaco", size: 12.0)
                       ?? NSFont.userFixedPitchFont(ofSize: 12.0)!

    // 脚本所在目录，用于定位同目录下的子进程二进制
    let workDir: String = {
        let fm = FileManager.default
        var path = CommandLine.arguments[0]

        // 如果是符号链接，解析到真实路径
        if let real = try? fm.destinationOfSymbolicLink(atPath: path) {
            path = real
        }

        // CommandLine.arguments[0] 可能是相对路径（"./foo.command" 甚至 "foo.command"），
        // 用当前工作目录拼成绝对路径
        if !path.hasPrefix("/") {
            let cwd = fm.currentDirectoryPath
            path = (cwd as NSString).appendingPathComponent(path)
        }

        // 标准化路径，消除 "./" 和 "../"
        path = (path as NSString).standardizingPath

        var dir = (path as NSString).deletingLastPathComponent
        // 万一还是空的（极端情况），兜底到 cwd
        if dir.isEmpty {
            dir = fm.currentDirectoryPath
        }
        return dir
    }()

    // ----- App lifecycle -----

    func applicationDidFinishLaunching(_ notification: Notification) {
        // 把 cwd 切到脚本所在目录，让子进程默认从这里读相对路径资源
        FileManager.default.changeCurrentDirectoryPath(workDir)

        setupStatusItem()
        setupConsoleWindow()
        startChild()
        sendStartupNotification()
    }

    func applicationWillTerminate(_ notification: Notification) {
        stopChild()
    }

    // 关闭日志窗口时只隐藏，不退出整个 App
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    // ----- 状态栏 -----

    /// 用 Core Graphics 绘制一个 18×18 的圆角矩形 + 镂空 P 模板图。
    /// template=true 后，系统会按菜单栏前景色填充（深色模式自动反色），
    /// 视觉重量与系统模板图标（钥匙、A、显示器等）一致。
    func makeTrayIcon() -> NSImage {
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size, flipped: false) { rect in
            // 1. 圆角矩形底
            let inset: CGFloat = 1
            let bgRect = rect.insetBy(dx: inset, dy: inset)
            let bg = NSBezierPath(roundedRect: bgRect, xRadius: 3.5, yRadius: 3.5)
            NSColor.black.setFill()  // template 模式下颜色不重要，系统会替换
            bg.fill()

            // 2. 在底色上"挖"出一个 P 字
            //    关键：用 capHeight 做视觉居中，而不是 text.size().height ——
            //    后者包含 ascent/descent/leading，直接拿来居中会让字形偏下。
            //    正确做法是把基线放在 (rect.height - capHeight) / 2 处。
            let font = NSFont.systemFont(ofSize: 14, weight: .heavy)
            let capHeight = font.capHeight
            let baselineY = (rect.height - capHeight) / 2

            let attrs: [NSAttributedString.Key: Any] = [
                .font: font,
                .foregroundColor: NSColor.black,
            ]
            let text = NSAttributedString(string: "P", attributes: attrs)
            let textWidth = text.size().width

            // NSAttributedString.draw(at:) 中 at 是字形左下角（基线下移 descender 的位置），
            // 所以最终 y = baselineY - descender。descender 是负数。
            let drawPoint = NSPoint(
                x: rect.midX - textWidth / 2,
                y: baselineY + font.descender  // descender 为负，相当于减
            )

            if let ctx = NSGraphicsContext.current?.cgContext {
                ctx.saveGState()
                ctx.setBlendMode(.destinationOut)
                text.draw(at: drawPoint)
                ctx.restoreGState()
            }
            return true
        }
        image.isTemplate = true
        return image
    }

    func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)

        // 状态栏旁边的系统图标（钥匙、A、显示器等）都是"实心填充"的模板图，
        // 裸字符在视觉重量上追不上。所以画一个圆角矩形底 + 镂空 P 的模板图标，
        // template=true 让系统自动按菜单栏前景色（Light/Dark 自适应）填充。
        statusItem.button?.image = makeTrayIcon()
        statusItem.button?.toolTip = APP_TITLE

        // 菜单
        let menu = NSMenu()

        menu.addItem(makeItem(title: "Show Console",
                              action: #selector(showConsole(_:))))
        menu.addItem(makeItem(title: "Hide Console",
                              action: #selector(hideConsole(_:))))

        menu.addItem(NSMenuItem.separator())

        // System Proxy 子菜单
        let proxyItem = NSMenuItem(title: "System Proxy", action: nil, keyEquivalent: "")
        let submenu = NSMenu()

        let disableItem = makeItem(title: "Disable",
                                   action: #selector(setProxyOff(_:)))
        submenu.addItem(disableItem)

        let pacItem = makeItem(title: "Auto Configuration (PAC)",
                               action: #selector(setProxyPac(_:)))
        pacItem.toolTip = "http://127.0.0.1:8087/proxy.pac"
        submenu.addItem(pacItem)

        let manualItem = makeItem(title: "Manual (HTTP/HTTPS)",
                                  action: #selector(setProxyHttp(_:)))
        manualItem.toolTip = "127.0.0.1:8087"
        submenu.addItem(manualItem)

        proxyItem.submenu = submenu
        menu.addItem(proxyItem)

        menu.addItem(NSMenuItem.separator())

        menu.addItem(makeItem(title: "Restart",
                              action: #selector(reload(_:))))
        menu.addItem(makeItem(title: "Quit \(APP_TITLE)",
                              action: #selector(quit(_:))))

        statusItem.menu = menu
    }

    private func makeItem(title: String, action: Selector) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self
        return item
    }

    // ----- 控制台窗口 -----

    func setupConsoleWindow() {
        let frame = NSRect(x: 0, y: 0, width: 640, height: 480)
        consoleWindow = NSWindow(
            contentRect: frame,
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        consoleWindow.title = APP_TITLE
        consoleWindow.delegate = self
        consoleWindow.isReleasedWhenClosed = false  // 关闭后能重新显示

        let scroll = NSScrollView(frame: frame)
        scroll.borderType = .noBorder
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.autoresizingMask = [.width, .height]

        consoleView = NSTextView(frame: frame)
        consoleView.backgroundColor = .black
        consoleView.isRichText = true
        consoleView.isEditable = false
        consoleView.isVerticallyResizable = true
        consoleView.isHorizontallyResizable = false
        consoleView.autoresizingMask = [.width]
        consoleView.font = consoleFont

        scroll.documentView = consoleView
        consoleWindow.contentView?.addSubview(scroll)
    }

    // ----- 子进程 -----

    // 解析 ENV：先看进程环境变量，再读同目录 .env
    // 返回 nil 表示两处都没拿到
    func resolveEnvName() -> String? {
        if let v = ProcessInfo.processInfo.environment["ENV"],
           !v.isEmpty {
            return v
        }
        let dotenvPath = workDir + "/.env"
        guard let content = try? String(contentsOfFile: dotenvPath,
                                        encoding: .utf8) else {
            return nil
        }
        for rawLine in content.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            var line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            // 兼容 `export ENV=foo`
            if line.hasPrefix("export ") {
                line = String(line.dropFirst("export ".count))
                       .trimmingCharacters(in: .whitespaces)
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces)
            guard key == "ENV" else { continue }
            var value = line[line.index(after: eq)...]
                          .trimmingCharacters(in: .whitespaces)
            // 去掉首尾匹配的引号
            if value.count >= 2 {
                let first = value.first!
                let last = value.last!
                if (first == "\"" && last == "\"") ||
                   (first == "'"  && last == "'") {
                    value = String(value.dropFirst().dropLast())
                }
            }
            if !value.isEmpty {
                return value
            }
        }
        return nil
    }

    func startChild() {
        appendToConsole("Working directory: \(workDir)\n",
                        color: ansiColors[7])

        let binPath = workDir + "/" + CHILD_BIN
        guard FileManager.default.isExecutableFile(atPath: binPath) else {
            appendToConsole("Cannot find executable: \(binPath)\n",
                            color: ansiColors[1])
            return
        }

        guard let envName = resolveEnvName() else {
            appendToConsole(
                "ENV not set. Define `ENV` in environment or in \(workDir)/.env\n",
                color: ansiColors[1])
            return
        }

        let configFile = "\(envName).yaml"
        let configPath = workDir + "/" + configFile
        guard FileManager.default.fileExists(atPath: configPath) else {
            appendToConsole("Config file not found: \(configPath)\n",
                            color: ansiColors[1])
            return
        }

        appendToConsole("Starting: \(CHILD_BIN) \(configFile)\n",
                        color: ansiColors[2])

        let p = Process()
        p.currentDirectoryURL = URL(fileURLWithPath: workDir)
        p.executableURL = URL(fileURLWithPath: binPath)
        p.arguments = [configFile]

        let outPipe = Pipe()
        let errPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = errPipe
        p.standardInput = FileHandle.nullDevice

        do {
            try p.run()
            self.childProcess = p
        } catch {
            appendToConsole("Failed to start \(CHILD_BIN): \(error)\n",
                            color: ansiColors[1])
            return
        }

        // 后台读 stdout / stderr，都 merge 到控制台
        startReading(handle: outPipe.fileHandleForReading)
        startReading(handle: errPipe.fileHandleForReading)
    }

    private func startReading(handle: FileHandle) {
        handle.readabilityHandler = { [weak self] h in
            let data = h.availableData
            guard !data.isEmpty else {
                h.readabilityHandler = nil
                return
            }
            // 解码到 String，回主线程刷新 UI
            let text = String(data: data, encoding: .utf8)
                ?? String(data: data, encoding: .isoLatin1)
                ?? ""
            DispatchQueue.main.async {
                self?.handleIncoming(text)
            }
        }
    }

    func stopChild() {
        if let p = childProcess, p.isRunning {
            p.terminate()
        }
        childProcess = nil
    }

    // ----- 输出解析与渲染 -----

    func handleIncoming(_ raw: String) {
        var line = raw

        // OSC 标题序列：\x1b]2;<title>\x07
        while let escIdx = line.range(of: "\u{1b}]2;"),
              let bellIdx = line.range(of: "\u{07}",
                                       range: escIdx.upperBound..<line.endIndex) {
            let title = String(line[escIdx.upperBound..<bellIdx.lowerBound])
            statusItem.button?.toolTip = title
            consoleWindow.title = title
            line.removeSubrange(escIdx.lowerBound..<bellIdx.upperBound)
        }

        // CSI 颜色序列：\x1b[<n>m
        var idx = line.startIndex
        var pendingText = ""
        while idx < line.endIndex {
            if line[idx] == "\u{1b}",
               line.distance(from: idx, to: line.endIndex) >= 2,
               line[line.index(after: idx)] == "[" {
                // 找到 'm' 终止
                if let mIdx = line.range(of: "m", range: idx..<line.endIndex) {
                    // 先把累积文本写出
                    if !pendingText.isEmpty {
                        appendToConsole(pendingText, color: currentColor)
                        pendingText = ""
                    }
                    let codeStart = line.index(idx, offsetBy: 2)
                    let codeStr = String(line[codeStart..<mIdx.lowerBound])
                    if let code = Int(codeStr) {
                        if (30..<38).contains(code) {
                            currentColor = ansiColors[code - 30]
                        } else if code == 0 {
                            currentColor = ansiColors[0]
                        }
                    }
                    idx = mIdx.upperBound
                    continue
                }
            }
            pendingText.append(line[idx])
            idx = line.index(after: idx)
        }
        if !pendingText.isEmpty {
            appendToConsole(pendingText, color: currentColor)
        }
    }

    func appendToConsole(_ text: String, color: NSColor) {
        let attrs: [NSAttributedString.Key: Any] = [
            .foregroundColor: color,
            .font: consoleFont,
        ]
        let attr = NSAttributedString(string: text, attributes: attrs)
        consoleView.textStorage?.append(attr)

        // 自动滚到底部（仅当用户已在底部时，避免打断阅读）
        let needScroll = NSMaxY(consoleView.visibleRect)
                       >= NSMaxY(consoleView.bounds) - 20
        if needScroll {
            consoleView.scrollRangeToVisible(
                NSRange(location: consoleView.string.utf16.count, length: 0)
            )
        }
    }

    // ----- 通知 -----
    // 用 osascript 投递系统通知。比 NSUserNotification 简单，且不依赖
    // app bundle（单文件脚本走不了 UNUserNotificationCenter，因为没有 bundle id）。
    func sendStartupNotification() {
        let body = "\(APP_TITLE) Started."
        let script = "display notification \"\" with title \"\(body)\" sound name \"default\""
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-e", script]
        try? task.run()
    }

    // ----- 菜单 actions -----

    @objc func showConsole(_ sender: Any?) {
        consoleWindow.center()
        consoleWindow.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc func hideConsole(_ sender: Any?) {
        consoleWindow.orderOut(nil)
    }

    @objc func setProxyOff(_ sender: Any?) {
        runAdminCommands([
            "networksetup -setwebproxystate Wi-Fi off",
            "networksetup -setsecurewebproxystate Wi-Fi off",
            "networksetup -setautoproxystate Wi-Fi off",
        ])
    }

    @objc func setProxyPac(_ sender: Any?) {
        runAdminCommands([
            "networksetup -setautoproxyurl Wi-Fi http://127.0.0.1:8087/proxy.pac",
            "networksetup -setautoproxystate Wi-Fi on",
            "networksetup -setwebproxystate Wi-Fi off",
            "networksetup -setsecurewebproxystate Wi-Fi off",
        ])
    }

    @objc func setProxyHttp(_ sender: Any?) {
        runAdminCommands([
            "networksetup -setwebproxy Wi-Fi 127.0.0.1 8087",
            "networksetup -setwebproxystate Wi-Fi on",
            "networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8087",
            "networksetup -setsecurewebproxystate Wi-Fi on",
            "networksetup -setautoproxystate Wi-Fi off",
        ])
    }

    @objc func reload(_ sender: Any?) {
        showConsole(sender)
        stopChild()
        consoleView.string = ""
        // 给一点时间让进程真正退出
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            self?.startChild()
        }
    }

    @objc func quit(_ sender: Any?) {
        stopChild()
        NSApp.terminate(nil)
    }

    // 用 osascript 弹系统授权框，执行需要 root 的 networksetup
    private func runAdminCommands(_ cmds: [String]) {
        let joined = cmds.joined(separator: " && ")
        // 转义双引号
        let escaped = joined.replacingOccurrences(of: "\"", with: "\\\"")
        let osa = "do shell script \"\(escaped)\" with administrator privileges"
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-e", osa]
        do {
            try task.run()
        } catch {
            appendToConsole("osascript failed: \(error)\n", color: ansiColors[1])
        }
    }
}


// ============================================================
// 启动
// ============================================================

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
// .accessory：无 Dock 图标，但仍能接收事件 / 显示窗口
app.setActivationPolicy(.accessory)
app.run()
