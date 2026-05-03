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
import Darwin
import Foundation
import Security
import SystemConfiguration

// ============================================================
// 常量
// ============================================================

// 子进程二进制名（与本脚本同目录）
let CHILD_BIN = "liner"

// 应用显示名 / 默认窗口标题 / tooltip
let APP_TITLE = "Liner"

// 系统代理入口默认从 ENV 对应的 YAML 里第一个 http.listen 推断。
// 也可用环境变量或同目录 .env 覆盖：
//   LINER_PROXY_HOST=127.0.0.1
//   LINER_PROXY_PORT=8080
//   LINER_PAC_URL=http://127.0.0.1:8080/proxy.pac
// 解析不到 http.listen 时使用下面的兜底值。
let DEFAULT_PROXY_HOST = "127.0.0.1"
let DEFAULT_PROXY_PORT = "8080"
let DEFAULT_PAC_PATH = "/proxy.pac"

// 控制台最多保留的 UTF-16 code units，避免长时间运行后 NSTextView 无限增长。
let CONSOLE_MAX_LENGTH = 2_000_000
let CONSOLE_TRIM_EXTRA = 100_000

// 重启/退出时等待 liner 优雅退出的最长时间。
let CHILD_STOP_TIMEOUT: TimeInterval = 5.0

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
    var authorization: AuthorizationRef?
    var expectedTerminationPids = Set<Int32>()
    var currentColor: NSColor = ansiColors[0]
    let consoleFont = NSFont(name: "Monaco", size: 12.0)
                       ?? NSFont.userFixedPitchFont(ofSize: 12.0)!
    lazy var dotEnv = readDotEnv()

    // 脚本所在目录，用于定位同目录下的子进程二进制
    let workDir: String = {
        let fm = FileManager.default
        let base = URL(fileURLWithPath: fm.currentDirectoryPath)
        let script = URL(fileURLWithPath: CommandLine.arguments[0],
                         relativeTo: base)
            .standardized
            .resolvingSymlinksInPath()
        return script.deletingLastPathComponent().path
    }()

    // ----- App lifecycle -----

    func applicationDidFinishLaunching(_ notification: Notification) {
        // 把 cwd 切到脚本所在目录，让子进程默认从这里读相对路径资源
        FileManager.default.changeCurrentDirectoryPath(workDir)

        setupStatusItem()
        setupConsoleWindow()
        if startChild() {
            sendNotification(title: APP_TITLE, body: "Started.")
        } else {
            showConsole(nil)
            sendNotification(title: APP_TITLE,
                             body: "Failed to start. Check the console.")
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        _ = stopChild()
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
        let proxySettings = resolveProxySettings()
        let proxyItem = NSMenuItem(title: "System Proxy", action: nil, keyEquivalent: "")
        let submenu = NSMenu()

        let disableItem = makeItem(title: "Disable",
                                   action: #selector(setProxyOff(_:)))
        submenu.addItem(disableItem)

        let pacItem = makeItem(title: "Auto Configuration (PAC)",
                               action: #selector(setProxyPac(_:)))
        pacItem.toolTip = proxySettings.pacURL
        submenu.addItem(pacItem)

        let manualItem = makeItem(title: "Manual (HTTP/HTTPS)",
                                  action: #selector(setProxyHttp(_:)))
        manualItem.toolTip = proxySettings.address
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

    struct ProxySettings {
        let host: String
        let port: String
        let pacURL: String

        var address: String {
            "\(ProxySettings.urlHost(host)):\(port)"
        }

        static func defaultFor(host: String, port: String) -> ProxySettings {
            ProxySettings(host: host,
                          port: port,
                          pacURL: "http://\(urlHost(host)):\(port)\(DEFAULT_PAC_PATH)")
        }

        static func urlHost(_ host: String) -> String {
            if host.contains(":") &&
               !host.hasPrefix("[") &&
               !host.hasSuffix("]") {
                return "[\(host)]"
            }
            return host
        }
    }

    // 解析同目录 .env，支持 `KEY=value` 和 `export KEY=value`。
    func readDotEnv() -> [String: String] {
        guard let content = try? String(contentsOfFile: workDir + "/.env",
                                        encoding: .utf8) else {
            return [:]
        }

        var values = [String: String]()
        for rawLine in content.components(separatedBy: .newlines) {
            var line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("export ") {
                line = String(line.dropFirst("export ".count))
                       .trimmingCharacters(in: .whitespaces)
            }

            let parts = line.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }

            let key = String(parts[0]).trimmingCharacters(in: .whitespaces)
            let value = stripMatchingQuotes(
                String(parts[1]).trimmingCharacters(in: .whitespaces))
            if !key.isEmpty && !value.isEmpty {
                values[key] = value
            }
        }
        return values
    }

    func resolveSetting(_ keys: [String]) -> String? {
        let env = ProcessInfo.processInfo.environment
        for key in keys {
            if let value = env[key], !value.isEmpty {
                return value
            }
        }

        for key in keys {
            if let value = dotEnv[key], !value.isEmpty {
                return value
            }
        }
        return nil
    }

    // 解析 ENV：先看进程环境变量，再读同目录 .env
    // 返回 nil 表示两处都没拿到
    func resolveEnvName() -> String? {
        resolveSetting(["ENV"])
    }

    func resolveProxySettings() -> ProxySettings {
        let inferred = inferProxySettingsFromConfig()
                       ?? ProxySettings.defaultFor(host: DEFAULT_PROXY_HOST,
                                                   port: DEFAULT_PROXY_PORT)
        let host = resolveSetting(["LINER_PROXY_HOST", "PROXY_HOST"]) ?? inferred.host
        let port = resolveSetting(["LINER_PROXY_PORT", "PROXY_PORT"]) ?? inferred.port
        let defaultPacURL = "http://\(ProxySettings.urlHost(host)):\(port)\(DEFAULT_PAC_PATH)"
        let pacURL = resolveSetting(["LINER_PAC_URL", "PAC_URL"])
                     ?? defaultPacURL
        return ProxySettings(host: host, port: port, pacURL: pacURL)
    }

    func inferProxySettingsFromConfig() -> ProxySettings? {
        guard let envName = resolveEnvName() else {
            return nil
        }

        let configFile = "\(envName).yaml"
        let configPath = workDir + "/" + configFile
        for path in configDataPaths(configPath: configPath) {
            guard let content = try? String(contentsOfFile: path,
                                            encoding: .utf8) else {
                continue
            }
            if let listen = firstHTTPListen(in: content),
               let settings = proxySettings(fromListen: listen) {
                return settings
            }
        }
        return nil
    }

    private func configDataPaths(configPath: String) -> [String] {
        let overlayDir = (configPath as NSString).deletingPathExtension + ".d"
        let overlays = (try? FileManager.default.contentsOfDirectory(atPath: overlayDir))?
            .sorted()
            .filter { $0.hasSuffix(".yaml") }
            .map { (overlayDir as NSString).appendingPathComponent($0) } ?? []
        return [configPath] + overlays
    }

    private func firstHTTPListen(in yaml: String) -> String? {
        var inHTTP = false
        var inListenBlock = false

        for rawLine in yaml.components(separatedBy: .newlines) {
            let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            if trimmed.hasPrefix("#") { continue }

            if !inHTTP {
                if trimmed == "http:" || trimmed.hasPrefix("http: ") {
                    inHTTP = true
                }
                continue
            }

            // 只扫 http: 顶层块，遇到下一个顶层 key 就停止。
            if let first = rawLine.first,
               !first.isWhitespace,
               !trimmed.hasPrefix("- ") {
                break
            }

            if inListenBlock {
                if trimmed.hasPrefix("- "),
                   let value = cleanYAMLScalar(String(trimmed.dropFirst(2))) {
                    return value
                }
                if !trimmed.hasPrefix("#") {
                    inListenBlock = false
                }
            }

            let candidate = trimmed.hasPrefix("- ")
                ? String(trimmed.dropFirst(2)).trimmingCharacters(in: .whitespaces)
                : trimmed
            guard candidate.hasPrefix("listen:") else {
                continue
            }

            let rawValue = String(candidate.dropFirst("listen:".count))
                .trimmingCharacters(in: .whitespaces)
            if rawValue.isEmpty {
                inListenBlock = true
            } else {
                return firstListenScalar(rawValue)
            }
        }

        return nil
    }

    private func firstListenScalar(_ raw: String) -> String? {
        var value = stripYAMLComment(raw)
        if value.hasPrefix("[") && value.hasSuffix("]") {
            value = value
                .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                .split(separator: ",", maxSplits: 1)
                .first
                .map(String.init) ?? ""
        }
        return cleanYAMLScalar(value)
    }

    private func cleanYAMLScalar(_ raw: String) -> String? {
        let value = stripYAMLComment(raw)
        guard !value.isEmpty && value != "|" && value != ">" else {
            return nil
        }
        return stripMatchingQuotes(value).trimmingCharacters(in: .whitespaces)
    }

    private func stripYAMLComment(_ raw: String) -> String {
        raw.split(separator: "#", maxSplits: 1)
            .first
            .map(String.init)?
            .trimmingCharacters(in: .whitespaces) ?? ""
    }

    private func stripMatchingQuotes(_ value: String) -> String {
        guard value.count >= 2,
              let first = value.first,
              let last = value.last,
              first == last,
              (first == "\"" || first == "'") else {
            return value
        }
        return String(value.dropFirst().dropLast())
    }

    private func proxySettings(fromListen rawListen: String) -> ProxySettings? {
        var listen = rawListen.trimmingCharacters(in: .whitespaces)
        if let scheme = listen.range(of: "://") {
            listen = String(listen[scheme.upperBound...])
        }
        if let slash = listen.firstIndex(of: "/") {
            listen = String(listen[..<slash])
        }
        if let question = listen.firstIndex(of: "?") {
            listen = String(listen[..<question])
        }

        let host: String
        let port: String
        if listen.hasPrefix("["),
           let close = listen.firstIndex(of: "]") {
            host = String(listen[listen.index(after: listen.startIndex)..<close])
            let rest = listen[listen.index(after: close)...]
            guard rest.hasPrefix(":") else { return nil }
            port = String(rest.dropFirst())
        } else if let colon = listen.lastIndex(of: ":") {
            host = String(listen[..<colon])
            port = String(listen[listen.index(after: colon)...])
        } else if Int(listen) != nil {
            host = DEFAULT_PROXY_HOST
            port = listen
        } else {
            return nil
        }

        guard let portNumber = Int(port),
              (1...65535).contains(portNumber) else {
            return nil
        }

        let normalizedHost = proxyHostForListenHost(host)
        return ProxySettings.defaultFor(host: normalizedHost,
                                        port: String(portNumber))
    }

    private func proxyHostForListenHost(_ host: String) -> String {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty ||
           trimmed == "*" ||
           trimmed == "0.0.0.0" ||
           trimmed == "::" ||
           trimmed == "::0" {
            return DEFAULT_PROXY_HOST
        }
        return trimmed
    }

    @discardableResult
    func startChild() -> Bool {
        appendToConsole("Working directory: \(workDir)\n",
                        color: ansiColors[7])

        if let p = childProcess, p.isRunning {
            appendToConsole("\(CHILD_BIN) is already running.\n",
                            color: ansiColors[3])
            return true
        }

        let binPath = workDir + "/" + CHILD_BIN
        guard FileManager.default.isExecutableFile(atPath: binPath) else {
            appendToConsole("Cannot find executable: \(binPath)\n",
                            color: ansiColors[1])
            return false
        }

        guard let envName = resolveEnvName() else {
            appendToConsole(
                "ENV not set. Define `ENV` in environment or in \(workDir)/.env\n",
                color: ansiColors[1])
            return false
        }

        let configFile = "\(envName).yaml"
        let configPath = workDir + "/" + configFile
        guard FileManager.default.fileExists(atPath: configPath) else {
            appendToConsole("Config file not found: \(configPath)\n",
                            color: ansiColors[1])
            return false
        }

        appendToConsole("Starting: \(CHILD_BIN) \(configFile)\n",
                        color: ansiColors[2])

        let p = Process()
        p.currentDirectoryURL = URL(fileURLWithPath: workDir)
        p.executableURL = URL(fileURLWithPath: binPath)
        p.arguments = [configFile]
        var environment = ProcessInfo.processInfo.environment
        environment["LINER_LOG_TO_STDERR"] = "1"
        p.environment = environment

        let outPipe = Pipe()
        let errPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = errPipe
        p.standardInput = FileHandle.nullDevice
        p.terminationHandler = { [weak self] process in
            DispatchQueue.main.async {
                self?.childDidTerminate(process)
            }
        }

        self.childProcess = p
        do {
            try p.run()
        } catch {
            if self.childProcess === p {
                self.childProcess = nil
            }
            appendToConsole("Failed to start \(CHILD_BIN): \(error)\n",
                            color: ansiColors[1])
            return false
        }

        // 后台读 stdout / stderr，都 merge 到控制台
        startReading(handle: outPipe.fileHandleForReading)
        startReading(handle: errPipe.fileHandleForReading)
        return true
    }

    private func startReading(handle: FileHandle) {
        handle.readabilityHandler = { [weak self] h in
            let data = h.availableData
            guard !data.isEmpty else {
                h.readabilityHandler = nil
                return
            }
            DispatchQueue.main.async {
                self?.handleIncoming(String(decoding: data, as: UTF8.self))
            }
        }
    }

    @discardableResult
    func stopChild() -> Bool {
        guard let p = childProcess else {
            return true
        }

        expectedTerminationPids.insert(p.processIdentifier)
        if p.isRunning {
            p.terminate()

            if !waitForExit(p, timeout: CHILD_STOP_TIMEOUT) {
                appendToConsole(
                    "\(CHILD_BIN) did not exit after \(Int(CHILD_STOP_TIMEOUT))s; killing it.\n",
                    color: ansiColors[3])
                Darwin.kill(p.processIdentifier, SIGKILL)
                _ = waitForExit(p, timeout: 2.0)
            }
        }

        if childProcess === p {
            childProcess = nil
        }
        return !p.isRunning
    }

    private func waitForExit(_ process: Process, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            RunLoop.current.run(mode: .default,
                                before: Date().addingTimeInterval(0.05))
        }
        return !process.isRunning
    }

    private func childDidTerminate(_ process: Process) {
        let expected = expectedTerminationPids.remove(process.processIdentifier) != nil
        if childProcess === process {
            childProcess = nil
        }
        guard !expected else { return }

        let status = process.terminationStatus
        let reason: String
        switch process.terminationReason {
        case .exit:
            reason = "exit status \(status)"
        case .uncaughtSignal:
            reason = "signal \(status)"
        @unknown default:
            reason = "status \(status)"
        }

        appendToConsole("\n\(CHILD_BIN) exited unexpectedly: \(reason)\n",
                        color: ansiColors[1])
        statusItem.button?.toolTip = "\(APP_TITLE) stopped: \(reason)"
        showConsole(nil)
        sendNotification(title: APP_TITLE,
                         body: "\(CHILD_BIN) stopped: \(reason)")
    }

    // ----- 输出解析与渲染 -----

    private func applyANSICodes(_ codeStr: String) {
        let parts = codeStr.split(separator: ";", omittingEmptySubsequences: false)
        if parts.isEmpty {
            currentColor = ansiColors[0]
            return
        }

        for part in parts {
            let code = Int(String(part)) ?? 0
            if (30..<38).contains(code) {
                currentColor = ansiColors[code - 30]
            } else if code == 0 || code == 39 {
                currentColor = ansiColors[0]
            }
        }
    }

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
                let codeStart = line.index(idx, offsetBy: 2)
                if let mRange = line.range(of: "m", range: codeStart..<line.endIndex) {
                    // 先把累积文本写出
                    if !pendingText.isEmpty {
                        appendToConsole(pendingText, color: currentColor)
                        pendingText = ""
                    }
                    let codeStr = String(line[codeStart..<mRange.lowerBound])
                    applyANSICodes(codeStr)
                    idx = mRange.upperBound
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
        // 自动滚到底部（仅当用户已在底部时，避免打断阅读）
        let needScroll = NSMaxY(consoleView.visibleRect)
                       >= NSMaxY(consoleView.bounds) - 20

        let attrs: [NSAttributedString.Key: Any] = [
            .foregroundColor: color,
            .font: consoleFont,
        ]
        let attr = NSAttributedString(string: text, attributes: attrs)
        consoleView.textStorage?.append(attr)
        trimConsoleIfNeeded()

        if needScroll {
            consoleView.scrollRangeToVisible(
                NSRange(location: consoleView.string.utf16.count, length: 0)
            )
        }
    }

    private func trimConsoleIfNeeded() {
        guard let storage = consoleView.textStorage else { return }
        let overflow = storage.length - CONSOLE_MAX_LENGTH
        guard overflow > 0 else { return }

        var deleteLength = min(storage.length,
                               overflow + CONSOLE_TRIM_EXTRA)
        if deleteLength < storage.length {
            let string = storage.string as NSString
            let searchRange = NSRange(
                location: deleteLength,
                length: min(4096, storage.length - deleteLength)
            )
            let newline = string.range(of: "\n", options: [], range: searchRange)
            if newline.location != NSNotFound {
                deleteLength = newline.location + newline.length
            }
        }

        storage.deleteCharacters(in: NSRange(location: 0,
                                             length: deleteLength))
    }

    // ----- 通知 -----
    private func appleScriptStringLiteral(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "\"\(escaped)\""
    }

    // 用 osascript 投递系统通知。比 NSUserNotification 简单，且不依赖
    // app bundle（单文件脚本走不了 UNUserNotificationCenter，因为没有 bundle id）。
    func sendNotification(title: String, body: String) {
        let script = "display notification \(appleScriptStringLiteral(body)) " +
                     "with title \(appleScriptStringLiteral(title)) " +
                     "sound name \"default\""
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

    enum ProxyMode {
        case off
        case pac
        case http
    }

    @objc func setProxyOff(_ sender: Any?) {
        applyProxyMode(.off)
    }

    @objc func setProxyPac(_ sender: Any?) {
        applyProxyMode(.pac)
    }

    @objc func setProxyHttp(_ sender: Any?) {
        applyProxyMode(.http)
    }

    @objc func reload(_ sender: Any?) {
        showConsole(sender)
        guard stopChild() else {
            appendToConsole("Restart aborted: \(CHILD_BIN) is still running.\n",
                            color: ansiColors[1])
            return
        }
        consoleView.string = ""
        if startChild() {
            sendNotification(title: APP_TITLE, body: "Restarted.")
        } else {
            showConsole(nil)
            sendNotification(title: APP_TITLE,
                             body: "Restart failed. Check the console.")
        }
    }

    @objc func quit(_ sender: Any?) {
        stopChild()
        NSApp.terminate(nil)
    }

    private func applyProxyMode(_ mode: ProxyMode) {
        let settings = resolveProxySettings()
        let modeName: String
        switch mode {
        case .off:
            modeName = "Disable"
        case .pac:
            modeName = "PAC \(settings.pacURL)"
        case .http:
            modeName = "HTTP/HTTPS \(settings.address)"
        }

        do {
            let services = try setSystemProxy(mode: mode, settings: settings)
            appendToConsole(
                "Applied System Proxy '\(modeName)' to: \(services.joined(separator: ", "))\n",
                color: ansiColors[2])
        } catch {
            appendToConsole("System proxy update failed: \(error.localizedDescription)\n",
                            color: ansiColors[1])
            showConsole(nil)
        }
    }

    private func setSystemProxy(mode: ProxyMode,
                                settings: ProxySettings) throws -> [String] {
        let prefs = try authorizedPreferences()
        guard let set = SCNetworkSetCopyCurrent(prefs),
              let services = SCNetworkSetCopyServices(set) as? [SCNetworkService] else {
            throw scError("read network services")
        }

        var changed = [String]()
        for service in services where SCNetworkServiceGetEnabled(service) {
            guard let proto = SCNetworkServiceCopyProtocol(
                service, kSCNetworkProtocolTypeProxies) else {
                continue
            }

            var config = (SCNetworkProtocolGetConfiguration(proto)
                          as? [String: Any]) ?? [:]
            applyProxyConfig(&config, mode: mode, settings: settings)

            guard SCNetworkProtocolSetConfiguration(proto, config as CFDictionary) else {
                throw scError("set proxy protocol")
            }
            changed.append((SCNetworkServiceGetName(service) as String?) ?? "Unknown")
        }

        guard !changed.isEmpty else {
            throw simpleError("no enabled network services found")
        }
        guard SCPreferencesCommitChanges(prefs) else {
            throw scError("commit proxy settings")
        }
        guard SCPreferencesApplyChanges(prefs) else {
            throw scError("apply proxy settings")
        }
        return changed
    }

    private func applyProxyConfig(_ config: inout [String: Any],
                                  mode: ProxyMode,
                                  settings: ProxySettings) {
        config[kSCPropNetProxiesHTTPEnable as String] = mode == .http ? 1 : 0
        config[kSCPropNetProxiesHTTPSEnable as String] = mode == .http ? 1 : 0
        config[kSCPropNetProxiesProxyAutoConfigEnable as String] = mode == .pac ? 1 : 0

        if mode == .http {
            let port = Int(settings.port) ?? 0
            config[kSCPropNetProxiesHTTPProxy as String] = settings.host
            config[kSCPropNetProxiesHTTPPort as String] = port
            config[kSCPropNetProxiesHTTPSProxy as String] = settings.host
            config[kSCPropNetProxiesHTTPSPort as String] = port
        } else if mode == .pac {
            config[kSCPropNetProxiesProxyAutoConfigURLString as String] = settings.pacURL
        }
    }

    private func authorizedPreferences() throws -> SCPreferences {
        if authorization == nil {
            var auth: AuthorizationRef?
            let flags: AuthorizationFlags = [
                .interactionAllowed,
                .extendRights,
                .preAuthorize,
            ]
            let status = AuthorizationCreate(nil, nil, flags, &auth)
            guard status == errAuthorizationSuccess, let auth = auth else {
                throw authorizationError(status)
            }
            authorization = auth
        }

        guard let prefs = SCPreferencesCreateWithAuthorization(
            nil, APP_TITLE as CFString, nil, authorization) else {
            throw scError("open network preferences")
        }
        return prefs
    }

    private func authorizationError(_ status: OSStatus) -> Error {
        let message = SecCopyErrorMessageString(status, nil) as String?
        return simpleError(message ?? "authorization failed: \(status)")
    }

    private func scError(_ context: String) -> Error {
        simpleError("\(context): \(String(cString: SCErrorString(SCError())))")
    }

    private func simpleError(_ message: String) -> Error {
        NSError(domain: APP_TITLE,
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: message])
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
