import AppKit
import SwiftUI

/// Activates the window; connections belong to the shared user runtime.
final class AppDelegate: NSObject, NSApplicationDelegate {
  /// A bare SwiftPM executable (e.g. run from Xcode) starts without a bundle
  /// and never becomes the key app, so text fields get no keyboard or paste.
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate()
  }
}

@main struct NetworkOrchestratorApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
  @State private var model = AppModel()
  @AppStorage("appearance") private var appearance = "system"
  @AppStorage("showMenuBar") private var showMenuBar = true
  var body: some Scene {
    WindowGroup("Network Orchestrator", id: "main") {
      ContentView(model: model).frame(minWidth: 960, minHeight: 640)
        .preferredColorScheme(appearance == "dark" ? .dark : appearance == "light" ? .light : nil)
    }
    .defaultSize(width: 1200, height: 780)
    .commands {
      CommandGroup(replacing: .newItem) {}
      CommandGroup(after: .toolbar) {
        Button(L10n.text("Refresh network")) { Task { await model.refresh() } }
          .keyboardShortcut("r", modifiers: .command)
      }
    }
    MenuBarExtra(isInserted: $showMenuBar) {
      MenuBarContent(model: model)
    } label: {
      Image(
        systemName: model.activeCount > 0 ? "network.badge.shield.half.filled" : "network")
    }
    .menuBarExtraStyle(.menu)
    Settings { NativeSettingsWindow(model: model).frame(width: 700) }
  }
}

/// The menu bar menu: what is connected, a switch per connection, and the
/// window. Works with the window closed; the model keeps polling.
struct MenuBarContent: View {
  @Bindable var model: AppModel
  @Environment(\.openWindow) private var openWindow
  private var profiles: [Profile] { model.snapshot?.profiles ?? [] }
  var body: some View {
    let active = profiles.filter { model.isRunning($0) }
    Text(
      active.isEmpty
        ? L10n.text("All disconnected")
        : L10n.text("native.connectedCount", ["count": String(active.count)]))
    Divider()
    if profiles.isEmpty {
      Text(L10n.text("native.menuBar.noConnections"))
    }
    ForEach(profiles) { profile in
      Toggle(
        profile.name,
        isOn: Binding(
          get: { model.isRunning(profile) },
          set: { _ in
            Task {
              await model.toggle(profile)
              // A helper prompt or a login sheet lives in the window.
              if model.helperPrompt || model.credentialRequest != nil { showWindow() }
            }
          })
      ).disabled(!model.canTryStart(profile) || model.pending.contains(profile.id))
    }
    Divider()
    Button(L10n.text("native.menuBar.disconnectAll")) { Task { await model.disconnectAll() } }
      .disabled(active.isEmpty)
    Button(L10n.text("native.menuBar.open")) { showWindow() }
    Divider()
    Button(L10n.text("native.menuBar.quit")) { NSApp.terminate(nil) }
      .keyboardShortcut("q")
  }
  private func showWindow() {
    openWindow(id: "main")
    NSApp.activate()
  }
}

struct NativeSettingsWindow: View {
  @Bindable var model: AppModel
  @Environment(\.colorScheme) private var scheme
  @AppStorage("appearance") private var appearance = "system"
  var body: some View {
    ScrollView { SettingsView(model: model).padding(.horizontal, 28).padding(.vertical, 21) }
      .environment(\.locale, Locale(identifier: L10n.shared.language))
      .environment(\.layoutDirection, L10n.shared.direction)
      .background(AppPalette(scheme: scheme).app).foregroundStyle(AppPalette(scheme: scheme).text)
      .environment(\.palette, AppPalette(scheme: scheme)).buttonStyle(TauriButtonStyle())
      .preferredColorScheme(appearance == "dark" ? .dark : appearance == "light" ? .light : nil)
  }
}
