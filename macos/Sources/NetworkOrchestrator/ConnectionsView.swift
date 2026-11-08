import AppKit
import SwiftUI
import UniformTypeIdentifiers

enum ConnectionModal: Identifiable {
  case add
  case importConfig(String?)
  case staticRoutes
  var id: String {
    switch self {
    case .add: "add"
    case .importConfig(let backend): "import-" + (backend ?? "auto")
    case .staticRoutes: "static"
    }
  }
}
struct ConnectionsView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @Binding var modal: ConnectionModal?
  @State private var collapsed = Set<String>()
  @State private var renaming: Profile?
  @State private var deleting: Profile?
  @State private var name = ""
  @State private var savingSet = false
  @State private var setName = ""
  @AppStorage("connectionsListWidth") private var storedListWidth = 400.0
  /// Live width while the splitter is dragged; persisted once on release so
  /// UserDefaults is not hit (and observers are not woken) on every frame.
  @State private var dragWidth: Double?
  @State private var dragStartWidth: Double?
  private var listWidth: Double { dragWidth ?? storedListWidth }
  var body: some View {
    VStack(alignment: .leading, spacing: 10.5) {
      HStack(spacing: 7) {
        Text(L10n.text("profiles.title")).font(.system(size: 14.7, weight: .semibold))
        Spacer()
        AppInput(placeholder: "profiles.searchPh", text: $model.search).frame(width: 240)
        Button(L10n.text(model.refreshing.isEmpty ? "common.refresh" : "detail.refreshing")) {
          Task { await model.refreshAll() }
        }.disabled(!model.refreshing.isEmpty || model.busy)
          .help(L10n.text("native.refreshAllHint"))
        Button(L10n.text("profiles.import")) { modal = .importConfig(nil) }
        Button(L10n.text("+ Add connection")) { modal = .add }.buttonStyle(
          TauriButtonStyle(kind: .accent))
      }
      notices
      if model.profiles.isEmpty {
        AppEmptyState {
          Text(
            model.search.isEmpty
              ? L10n.text("profiles.empty")
              : L10n.text("profiles.noMatch", ["query": model.search]))
        }
      } else {
        setsBar
        HStack(alignment: .top, spacing: 0) {
          list.frame(width: listWidth)
          splitter
          if let profile = model.selectedProfile {
            ProfileDetailView(
              model: model, profile: profile,
              onRename: {
                name = profile.name
                renaming = profile
              }, onDelete: { deleting = profile }
            ).id(profile.id)
          }
        }
      }
    }
    .sheet(item: $renaming) { profile in
      AppModal(title: "Rename connection", width: 440, onClose: { renaming = nil }) {
        VStack(alignment: .leading, spacing: 14) {
          AppInput(placeholder: "Name", text: $name)
          HStack {
            Spacer()
            Button(L10n.text("Cancel")) { renaming = nil }
            Button(L10n.text("Save")) {
              Task { if await model.rename(profile, name: name) { renaming = nil } }
            }.buttonStyle(TauriButtonStyle(kind: .accent)).disabled(
              name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.busy)
          }
        }.padding(14)
      }.environment(\.palette, p)
    }
    .alert(
      L10n.text("Delete connection?"),
      isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })
    ) {
      Button(L10n.text("Cancel"), role: .cancel) { deleting = nil }
      Button(L10n.text("Delete"), role: .destructive) {
        if let profile = deleting { Task { await model.remove(profile) } }
        deleting = nil
      }
    } message: {
      Text(L10n.text("The saved profile and its managed configuration will be removed."))
    }
  }
  /// Draggable divider between the list and the detail pane.
  private var splitter: some View {
    Rectangle().fill(p.border).frame(width: 1).padding(.horizontal, 14)
      .frame(maxHeight: .infinity)
      .contentShape(Rectangle())
      .onHover { inside in inside ? NSCursor.resizeLeftRight.push() : NSCursor.pop() }
      // Global space: the splitter moves with the cursor, so a local
      // translation would feed back into itself and make the panes jitter.
      .gesture(
        DragGesture(minimumDistance: 1, coordinateSpace: .global)
          .onChanged { value in
            let start = dragStartWidth ?? storedListWidth
            dragStartWidth = start
            var transaction = Transaction()
            transaction.disablesAnimations = true
            withTransaction(transaction) {
              dragWidth = min(max(start + value.translation.width, 300), 640)
            }
          }
          .onEnded { _ in
            if let dragWidth { storedListWidth = dragWidth }
            dragWidth = nil
            dragStartWidth = nil
          })
  }
  /// Saved combinations of connections, applied in one click.
  private var setsBar: some View {
    let running = (model.snapshot?.profiles ?? []).filter { model.isRunning($0) }
    return HStack(spacing: 7) {
      Text(L10n.text("sets.label").uppercased()).font(.system(size: 10.08, weight: .semibold))
        .tracking(0.7).foregroundStyle(p.muted)
      ForEach(model.connectionSets) { set in
        let active = Set(running.map(\.id)) == Set(set.profileIds)
        Button(set.name) { Task { await model.applySet(set) } }
          .buttonStyle(TauriButtonStyle(kind: active ? .accent : .chip, compact: true))
          .help(L10n.text("sets.applyTitle", ["count": String(set.profileIds.count)]))
          .contextMenu {
            Button(L10n.text("sets.deleteTitle"), role: .destructive) { Task { await model.deleteSet(set) } }
          }
      }
      Button(L10n.text("sets.saveCurrent")) {
        setName = ""
        savingSet = true
      }.buttonStyle(TauriButtonStyle(kind: .chip, compact: true)).disabled(running.isEmpty)
        .help(L10n.text(running.isEmpty ? "sets.connectFirst" : "sets.saveTitle"))
      Spacer()
    }
    .alert(L10n.text("sets.modalTitle"), isPresented: $savingSet) {
      TextField(L10n.text("sets.namePh"), text: $setName)
      Button(L10n.text("Cancel"), role: .cancel) {}
      Button(L10n.text("Save")) { Task { await model.saveCurrentSet(name: setName) } }
    } message: {
      Text(L10n.text("sets.willInclude", ["count": String(running.count)]))
    }
  }
  @ViewBuilder private var notices: some View {
    if model.importSkippedCount > 0 {
      Text(
        L10n.text(
          "Skipped {count} unsupported or invalid endpoints.",
          ["count": String(model.importSkippedCount)])
      ).font(.system(size: 11.9)).foregroundStyle(p.secondary)
    }
    if model.canStartConnections, let runtime = model.runtime, !runtime.xrayInstalled,
      model.snapshot?.profiles.contains(where: { $0.backend == "xray" }) ?? false
    {
      NoticeBar(color: "info") {
        Text(L10n.text("native.xrayMissing", ["version": runtime.xrayVersion]))
        Spacer()
        Button(L10n.text(model.installingXray ? "native.installing" : "native.installXray")) {
          Task { await model.installXray() }
        }.buttonStyle(TauriButtonStyle(kind: .accent, compact: true)).disabled(
          model.installingXray)
        Button(L10n.text("native.installXrayFile")) {
          let panel = NSOpenPanel()
          panel.allowedContentTypes = [.zip]
          panel.message = L10n.text("native.installXrayFileHint")
          if panel.runModal() == .OK, let url = panel.url {
            Task { await model.installXray(archive: url) }
          }
        }.buttonStyle(TauriButtonStyle(compact: true)).disabled(model.installingXray)
      }
    }
    if let notice = model.notice {
      NoticeBar(color: notice == "native.proxyOverridden" || notice.hasPrefix("events.autoConnect") ? "warn" : "up") {
        Text(
          L10n.text(
            notice,
            [
              "iface": model.primaryInterface ?? "",
              "n": String(model.autoConnectFailures),
            ]))
        Spacer()
        Button(L10n.text("common.dismiss")) { model.notice = nil }.buttonStyle(
          TauriButtonStyle(compact: true))
      }
    }
  }
  private var list: some View {
    VStack(alignment: .leading, spacing: 0) {
      ForEach(["wireGuard", "openVpn", "xray", "none"], id: \.self) { backend in
        let profiles = model.profiles.filter { $0.backend == backend }
        if !profiles.isEmpty {
          Button {
            if !collapsed.insert(backend).inserted { collapsed.remove(backend) }
          } label: {
            HStack(spacing: 7) {
              NativeIcon(name: "ChevronIcon", size: 12).rotationEffect(
                .degrees(collapsed.contains(backend) ? 0 : 180))
              NativeIcon(name: NativeIcon.backend(backend), size: 15).foregroundStyle(
                p[backendTint(backend)])
              Text(L10n.text(profiles[0].kind)).font(.system(size: 11.2, weight: .semibold))
              Text("· \(profiles.count)").font(.system(size: 10.08)).foregroundStyle(p.muted)
              Spacer()
            }.foregroundStyle(p.secondary).padding(.horizontal, 8).padding(.top, 14)
              .padding(.bottom, 5).contentShape(Rectangle())
          }.buttonStyle(.plain).accessibilityLabel(L10n.text(profiles[0].kind))
          Rectangle().fill(p.border).frame(height: 1)
          if !collapsed.contains(backend) {
            ForEach(profiles) { profile in row(profile) }
          }
        }
      }
      if !model.externalVPNs.isEmpty || model.netbird?.installed == true
        || model.tailscale?.installed == true
      {
        Text(L10n.text("profiles.external")).font(.system(size: 11.2, weight: .semibold))
          .foregroundStyle(p.secondary).padding(.horizontal, 8).padding(.top, 14).padding(
            .bottom, 5)
        Rectangle().fill(p.border).frame(height: 1)
        if let netbird = model.netbird, netbird.installed { netbirdRow(netbird) }
        if let tailscale = model.tailscale, tailscale.installed { tailscaleRow(tailscale) }
        ForEach(model.externalVPNs.filter { !model.isTailscaleService($0) }) { vpn in
          externalRow(vpn)
        }
      }
    }
  }
  /// Tailscale: the user's own daemon, switched on and off like another app's
  /// VPN, with a note when the app is keeping it reachable next to a tunnel.
  private func tailscaleRow(_ state: TailscaleState) -> some View {
    let service = model.externalVPNs.first { model.isTailscaleService($0) }
    let busy =
      model.tailscaleBusy || state.state == "connecting"
      || (service.map { model.switchingExternal.contains($0.id) } ?? false)
    return HStack(spacing: 8) {
      StateDot(
        state: state.state == "connected" ? "running" : state.state == "needsLogin" ? "failed" : "stopped")
      NativeIcon(name: "VpnIcon", size: 14).foregroundStyle(p.secondary)
      VStack(alignment: .leading, spacing: 1) {
        Text("Tailscale").font(.system(size: 12.3, weight: .semibold)).lineLimit(1)
        Text(tailscaleSubtitle(state)).font(.system(size: 10.5))
          .foregroundStyle(state.state == "needsLogin" ? p["warn"] : p.muted).lineLimit(2)
      }
      Spacer(minLength: 8)
      if let page = state.authUrl.flatMap({ URL(string: $0) }) {
        Menu {
          Button(L10n.text("native.tailscale.signIn")) { NSWorkspace.shared.open(page) }
        } label: {
          NativeIcon(name: "DotsVerticalIcon", size: 14).frame(width: 22, height: 22)
        }.menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).foregroundStyle(p.secondary)
          .frame(width: 22)
      }
      if busy {
        Spinner(size: 12).frame(width: 34)
      } else {
        Button {
          Task { await model.toggleTailscale() }
        } label: {
          Capsule().fill(state.isOn ? p["up"] : p.border).frame(width: 34, height: 20).overlay(
            alignment: state.isOn ? .trailing : .leading
          ) {
            Circle().fill(.white).frame(width: 16, height: 16).padding(2)
          }
        }.buttonStyle(.plain).disabled(!state.canToggle)
          .help(L10n.text(state.isOn ? "common.disconnect" : "common.connect"))
          .accessibilityLabel(L10n.text(state.isOn ? "common.disconnect" : "common.connect"))
      }
    }
    .padding(.horizontal, 8).padding(.vertical, 5)
    .overlay(alignment: .bottom) { Rectangle().fill(p.border).frame(height: 1) }
  }
  private func tailscaleSubtitle(_ state: TailscaleState) -> String {
    switch state.state {
    case "connected":
      var parts = [state.ip ?? ""]
      if let online = state.peersOnline, let total = state.peersTotal {
        parts.append(
          L10n.text(
            "native.tailscale.peers", ["online": String(online), "total": String(total)]))
      }
      if state.exitNode == true { parts.append(L10n.text("native.tailscale.exitNode")) }
      let guardState = model.tailscaleGuard?.state
      if guardState == "protected" {
        parts.append(L10n.text("native.tailscale.guarded"))
      } else if guardState == "unsupported" && !model.ownTunnelInterfaces.isEmpty {
        parts.append(L10n.text("native.tailscale.guardOutdated"))
      }
      return parts.filter { !$0.isEmpty }.joined(separator: " · ")
    case "connecting": return L10n.text("native.tailscale.connecting")
    case "needsLogin": return L10n.text("native.tailscale.needsLogin")
    case "unavailable": return L10n.text("native.tailscale.unavailable")
    default: return L10n.text("native.tailscale.disconnected")
    }
  }
  /// NetBird: the user's own daemon, switched on and off like another app's VPN.
  private func netbirdRow(_ state: NetBirdState) -> some View {
    let busy = model.netbirdBusy
    return HStack(spacing: 8) {
      StateDot(state: state.state == "connected" ? "running" : state.state == "needsLogin" ? "failed" : "stopped")
      NativeIcon(name: "VpnIcon", size: 14).foregroundStyle(p.secondary)
      VStack(alignment: .leading, spacing: 1) {
        Text("NetBird").font(.system(size: 12.3, weight: .semibold)).lineLimit(1)
        Text(netbirdSubtitle(state)).font(.system(size: 10.5))
          .foregroundStyle(state.state == "needsLogin" ? p["warn"] : p.muted).lineLimit(2)
      }
      Spacer(minLength: 8)
      Menu {
        Button(L10n.text("native.netbird.setup")) { model.showingNetBirdSetup = true }
      } label: {
        NativeIcon(name: "DotsVerticalIcon", size: 14).frame(width: 22, height: 22)
      }.menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).foregroundStyle(p.secondary)
        .frame(width: 22)
      if busy || state.state == "connecting" {
        Spinner(size: 12).frame(width: 34)
      } else {
        Button {
          Task { await model.toggleNetBird() }
        } label: {
          Capsule().fill(state.isOn ? p["up"] : p.border).frame(width: 34, height: 20).overlay(
            alignment: state.isOn ? .trailing : .leading
          ) {
            Circle().fill(.white).frame(width: 16, height: 16).padding(2)
          }
        }.buttonStyle(.plain).disabled(!state.canToggle)
          .help(L10n.text(state.isOn ? "common.disconnect" : "common.connect"))
          .accessibilityLabel(L10n.text(state.isOn ? "common.disconnect" : "common.connect"))
      }
    }
    .padding(.horizontal, 8).padding(.vertical, 5)
    .overlay(alignment: .bottom) { Rectangle().fill(p.border).frame(height: 1) }
  }
  private func netbirdSubtitle(_ state: NetBirdState) -> String {
    switch state.state {
    case "connected":
      var parts = [state.ip.map { String($0.split(separator: "/").first ?? "") } ?? ""]
      if let connected = state.peersConnected, let total = state.peersTotal {
        parts.append(
          L10n.text(
            "native.netbird.peers", ["connected": String(connected), "total": String(total)]))
      }
      if let until = Self.sessionEnd(state.sessionExpiresAt) {
        parts.append(L10n.text("native.netbird.session", ["time": until]))
      }
      return parts.filter { !$0.isEmpty }.joined(separator: " · ")
    case "connecting": return L10n.text("native.netbird.connecting")
    case "needsLogin": return L10n.text("native.netbird.needsLogin")
    case "daemonStopped": return L10n.text("native.netbird.stopped")
    case "unavailable": return L10n.text("native.netbird.unavailable")
    default: return L10n.text("native.netbird.disconnected")
    }
  }
  /// "09:10" for a session that ends today or tomorrow; nothing when far away.
  private static func sessionEnd(_ iso: String?) -> String? {
    guard let iso else { return nil }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    guard let date = formatter.date(from: iso) ?? ISO8601DateFormatter().date(from: iso),
      date.timeIntervalSinceNow > 0, date.timeIntervalSinceNow < 48 * 3600
    else { return nil }
    return date.formatted(date: .omitted, time: .shortened)
  }
  private func externalRow(_ vpn: ExternalVpn) -> some View {
    let connected = vpn.state == "connected"
    let busy =
      model.switchingExternal.contains(vpn.id) || vpn.state == "connecting"
      || vpn.state == "disconnecting"
    return HStack(spacing: 8) {
      StateDot(state: connected ? "running" : "stopped")
      NativeIcon(name: "VpnIcon", size: 14).foregroundStyle(p.secondary)
      VStack(alignment: .leading, spacing: 1) {
        Text(vpn.name).font(.system(size: 12.3, weight: .semibold)).lineLimit(1)
        if let provider = vpn.provider {
          Text(provider).font(.system(size: 10.5)).foregroundStyle(p.muted).lineLimit(1)
        }
      }
      Spacer(minLength: 8)
      AppBadge(text: "detail.external", color: "warn")
      if busy {
        Spinner(size: 12).frame(width: 34)
      } else {
        Button {
          Task { await model.setExternalVPN(vpn, connect: !connected) }
        } label: {
          Capsule().fill(connected ? p["up"] : p.border).frame(width: 34, height: 20).overlay(
            alignment: connected ? .trailing : .leading
          ) {
            Circle().fill(.white).frame(width: 16, height: 16).padding(2)
          }
        }.buttonStyle(.plain).disabled(!vpn.enabled)
          .help(L10n.text(connected ? "common.disconnect" : "common.connect"))
          .accessibilityLabel(L10n.text(connected ? "common.disconnect" : "common.connect"))
      }
    }
    .padding(.horizontal, 8).padding(.vertical, 5)
    .overlay(alignment: .bottom) { Rectangle().fill(p.border).frame(height: 1) }
  }
  private func row(_ profile: Profile) -> some View {
    let selected = model.selectedProfile?.id == profile.id
    let state = model.status(profile)?.state ?? "stopped"
    return HStack(spacing: 8) {
      StateDot(state: state)
      NativeIcon(name: NativeIcon.backend(profile.backend), size: 14).foregroundStyle(
        p[backendTint(profile.backend)])
      // A subscription reads as a group: its name, then the chosen server.
      VStack(alignment: .leading, spacing: 1) {
        Text(profile.groupName).font(.system(size: 12.3, weight: .semibold)).lineLimit(1)
        if let server = model.activeServer(profile), server != profile.groupName {
          Text(profile.serverLabel(server)).font(.system(size: 10.5)).foregroundStyle(
            p.secondary
          ).lineLimit(1)
        }
      }
      Spacer(minLength: 8)
      Text(rowMeta(profile)).font(.system(size: 11, design: .monospaced)).foregroundStyle(
        p.muted
      ).lineLimit(1)
      ConnectionSwitch(model: model, profile: profile)
    }
    .padding(.horizontal, 8).padding(.vertical, 5)
    .background(selected ? p["bg-elev"] : .clear)
    .overlay(alignment: .leading) {
      if selected || state == "running" || state == "failed" {
        Rectangle().fill(selected ? p.accent : state == "running" ? p["up"] : p["down"]).frame(
          width: 2)
      }
    }
    .overlay(alignment: .bottom) { Rectangle().fill(p.border).frame(height: 1) }
    .contentShape(Rectangle())
    .onTapGesture { model.selectedProfileID = profile.id }
    .draggable(profile.id)
    .dropDestination(for: String.self) { ids, _ in
      guard let id = ids.first, id != profile.id,
        let dragged = model.snapshot?.profiles.first(where: { $0.id == id }),
        dragged.backend == profile.backend
      else { return false }
      Task { await model.move(dragged, to: profile) }
      return true
    }
    .contextMenu {
      if model.canStart(profile) {
        Button(L10n.text(model.isRunning(profile) ? "common.disconnect" : "common.connect")) {
          Task { await model.toggle(profile) }
        }
        Divider()
      }
      Button(L10n.text("Rename")) {
        name = profile.name
        renaming = profile
      }
      Button(L10n.text("Inspect configuration")) { Task { await model.inspect(profile) } }
      Divider()
      Button(L10n.text("detail.moveUp")) { Task { await model.move(profile, by: -1) } }
      Button(L10n.text("detail.moveDown")) { Task { await model.move(profile, by: 1) } }
      Divider()
      Button(L10n.text("Delete"), role: .destructive) { deleting = profile }
    }
    .accessibilityElement(children: .combine).accessibilityAddTraits(
      selected ? [.isSelected, .isButton] : [.isButton])
  }
  private func rowMeta(_ profile: Profile) -> String {
    if profile.backend == "xray", let port = profile.xraySocksPort { return ":\(port)" }
    return profile.interfaceName.isEmpty ? "—" : profile.interfaceName
  }
}

func backendTint(_ backend: String) -> String {
  switch backend {
  case "wireGuard": "wg-color"
  case "openVpn": "ovpn-color"
  case "xray": "xray-color"
  default: "none-color"
  }
}

struct StateDot: View {
  @Environment(\.palette) private var p
  let state: String
  var body: some View {
    Circle().fill(state == "running" ? p["up"] : state == "failed" ? p["down"] : p["unknown"])
      .frame(width: 7, height: 7)
  }
}

struct NoticeBar<Content: View>: View {
  @Environment(\.palette) private var p
  let color: String
  @ViewBuilder let content: Content
  var body: some View {
    HStack(spacing: 10.5) { content }.font(.system(size: 11.9)).padding(.horizontal, 12)
      .padding(.vertical, 7).background(p[color + "-bg"]).overlay(
        RoundedRectangle(cornerRadius: 6).stroke(p[color + "-border"], lineWidth: 1)
      ).clipShape(RoundedRectangle(cornerRadius: 6))
  }
}

/// Real on/off switch for connections this client can start; others render a
/// disabled switch explaining that the privileged helper is still missing.
struct ConnectionSwitch: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let profile: Profile
  var body: some View {
    let running = model.isRunning(profile)
    let busy = model.pending.contains(profile.id)
    let enabled =
      model.canTryStart(profile)
      && (model.runtime?.xrayInstalled ?? false) && !busy
    Button {
      Task { await model.toggle(profile) }
    } label: {
      Capsule().fill(running ? p["up"] : p.border).frame(width: 34, height: 20).overlay(
        alignment: running ? .trailing : .leading
      ) {
        Circle().fill(.white).frame(width: 16, height: 16).shadow(
          color: .black.opacity(0.2), radius: 1, y: 1
        ).padding(2)
      }.opacity(busy ? 0.6 : 1).animation(.easeOut(duration: 0.12), value: running)
    }.buttonStyle(.plain).disabled(!enabled)
      .help(
        L10n.text(
          model.modeLocks(profile)
            ? "profiles.modeManagedOnly"
            : !model.canStart(profile) && model.canStartConnections
            ? "native.helperRequired"
            : running ? "common.disconnect" : "common.connect")
      )
      .accessibilityLabel(L10n.text(running ? "common.disconnect" : "common.connect"))
  }
}

/// What the subscription provider says about itself: title, announcement and
/// support / account links (https only, opened in the default browser).
struct PanelInfoView: View {
  @Environment(\.palette) private var p
  let subscription: SubscriptionMeta
  let profileName: String
  var body: some View {
    let links: [(String, URL)] = [
      ("native.panelSupport", subscription.supportUrl),
      ("native.panelAccount", subscription.webPageUrl),
    ].compactMap { label, value in
      guard let value, let url = URL(string: value), ["https", "http"].contains(url.scheme ?? "")
      else { return nil }
      return (label, url)
    }
    let skipped = subscription.skippedProtocols ?? []
    if subscription.providerTitle != nil || subscription.announce != nil || !links.isEmpty
      || !skipped.isEmpty
    {
      VStack(alignment: .leading, spacing: 5) {
        if let title = subscription.providerTitle, title != profileName {
          Text(title).font(.system(size: 11.9, weight: .semibold))
        }
        if let announce = subscription.announce {
          Text(announce).font(.system(size: 11.9)).foregroundStyle(p.secondary)
            .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
        }
        if !skipped.isEmpty {
          Text(L10n.text("native.skippedProtocols", ["list": skipped.joined(separator: ", ")]))
            .font(.system(size: 10.92)).foregroundStyle(p.muted)
        }
        if !links.isEmpty {
          HStack(spacing: 7) {
            ForEach(links, id: \.0) { label, url in
              Button(L10n.text(label)) { NSWorkspace.shared.open(url) }
                .buttonStyle(TauriButtonStyle(compact: true)).help(url.host() ?? "")
            }
          }.padding(.top, 2)
        }
      }
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(.horizontal, 12).padding(.vertical, 9)
      .background(p["info-bg"], in: RoundedRectangle(cornerRadius: 6))
      .overlay(RoundedRectangle(cornerRadius: 6).stroke(p["info-border"], lineWidth: 1))
    }
  }
}

struct ProfileDetailView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State private var editingRules = false
  @State private var showingLog = false
  @State private var showingDiagnostics = false
  @State private var editingNetworks = false
  let profile: Profile
  let onRename: () -> Void
  let onDelete: () -> Void
  var body: some View {
    let status = model.status(profile)
    let running = status?.state == "running"
    let proxyOwner = model.runtime?.systemProxyOwner == profile.id
    VStack(alignment: .leading, spacing: 0) {
      HStack(alignment: .top, spacing: 10.5) {
        NativeIcon(name: NativeIcon.backend(profile.backend), size: 18)
          .foregroundStyle(p[backendTint(profile.backend)]).frame(width: 34, height: 34)
          .background(p[backendTint(profile.backend)].opacity(0.14), in: Circle())
        VStack(alignment: .leading, spacing: 3) {
          HStack(spacing: 7) {
            Text(profile.name).font(.system(size: 14.7, weight: .semibold)).lineLimit(1)
            if profile.backend != "none" { AppBadge(text: "detail.managed") }
            if proxyOwner { AppBadge(text: "native.systemProxy", color: "up") }
            if profile.runsTunnel && profile.isSecondary {
              AppBadge(text: "native.roleSecondary", color: "info")
            }
          }
          Text(statusLine(status)).font(.system(size: 11.2)).foregroundStyle(
            status?.state == "failed" ? p["down"] : p.muted
          ).lineLimit(2)
        }
        Spacer()
        ConnectionSwitch(model: model, profile: profile)
        Menu {
          Button(L10n.text("Rename"), action: onRename)
          Button(L10n.text("Inspect configuration")) { Task { await model.inspect(profile) } }
          Button(L10n.text("detail.diagnostics")) { showingDiagnostics = true }
          if profile.backend == "xray" || profile.backend == "openVpn" {
            Button(L10n.text("native.connectionLog")) { showingLog = true }
          }
          if profile.backend == "xray" {
            Divider()
            Button(L10n.text("native.openBrowser")) { Task { await model.openBrowser(profile) } }.disabled(
              !running)
            Button(L10n.text("native.copyTerminal")) { Task { await model.copyTerminalProxy(profile) } }
          }
          if profile.backend == "openVpn" {
            Button(L10n.text("native.credentials.forget")) { Task { await model.forgetCredentials(profile) } }
          }
          Divider()
          Button(L10n.text("Delete"), role: .destructive, action: onDelete)
        } label: {
          NativeIcon(name: "DotsVerticalIcon", size: 16).frame(width: 28, height: 28)
        }.menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden).foregroundStyle(
          p.secondary
        ).frame(width: 28).help(L10n.text("detail.actions"))
      }.padding(.bottom, 10.5)
      Rectangle().fill(p.border).frame(height: 1).padding(.bottom, 7)
      if let subscription = profile.subscription {
        PanelInfoView(subscription: subscription, profileName: profile.groupName)
          .padding(.bottom, 7)
      }
      row("detail.backend", L10n.text(profile.kind), mono: false)
      if let server = model.activeServer(profile) {
        row("native.server", server, mono: false)
      }
      if let usage = profile.subscription?.userInfo {
        row("detail.traffic", Self.usageText(usage), mono: false)
      }
      if profile.backend != "xray" {
        // The live device the helper created, else what the profile declares.
        let live = model.status(profile)?.interfaceName
        row(
          "detail.interface",
          live ?? (profile.interfaceName.isEmpty
            ? L10n.text("detail.notAssigned") : profile.interfaceName))
      }
      if profile.backend == "xray" && model.canStartConnections { modePicker }
      if model.canTryStart(profile) { autoConnectRow }
      if profile.runsTunnel && model.canStartConnections { roleRows }
      if profile.isStatic && model.canTryStart(profile) { waitRow }
      if profile.isTun {
        row(
          "detail.interface",
          model.status(profile)?.interfaceName ?? L10n.text("detail.notAssigned"))
      } else {
        if let port = profile.xraySocksPort { row("SOCKS5", "127.0.0.1:\(port)", translate: false) }
        if let port = profile.xrayHttpPort {
          row("HTTP CONNECT", "127.0.0.1:\(port)", translate: false)
        }
      }
      if profile.startsWithoutHelper && model.canStartConnections {
        HStack {
          VStack(alignment: .leading, spacing: 2) {
            Text(L10n.text("native.systemProxy")).foregroundStyle(p.muted)
            Text(L10n.text("native.systemProxyHint")).font(.system(size: 10.08)).foregroundStyle(
              p.muted)
          }
          Spacer()
          Toggle(
            "",
            isOn: Binding(
              get: { proxyOwner },
              set: { value in Task { await model.setSystemProxy(profile, enabled: value) } })
          ).toggleStyle(.switch).controlSize(.small).labelsHidden().disabled(
            !running || (!proxyOwner && model.runtime?.systemProxyOwner != nil))
        }.font(.system(size: 11.9)).padding(.vertical, 5)
        if running {
          HStack(spacing: 7) {
            Button(L10n.text("native.openBrowser")) { model.openBrowser(profile) }.buttonStyle(
              TauriButtonStyle(compact: true))
            Button(L10n.text("native.copyTerminal")) { model.copyTerminalProxy(profile) }
              .buttonStyle(TauriButtonStyle(compact: true))
          }.padding(.vertical, 5)
        }
      }
      if profile.backend == "xray" { routingRules }
      tunnelConfig
      endpoints
      if !profile.routes.isEmpty {
        section("detail.routes")
        ForEach(Array(profile.routes.enumerated()), id: \.offset) { _, route in
          HStack(spacing: 7) {
            Text("• " + route.destination).font(.system(size: 11.9, design: .monospaced))
            Text(L10n.text("detail.metric", ["n": String(route.metric)])).font(
              .system(size: 9.8)
            ).foregroundStyle(p.muted).padding(.horizontal, 5).padding(.vertical, 1).background(
              p["bg-elev"], in: Capsule())
          }.padding(.vertical, 2)
        }
      }
      Spacer(minLength: 0)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .task(id: profile.id) { await model.loadInspection(profile) }
    .sheet(isPresented: $showingDiagnostics) {
      DiagnosticsSheet(model: model, profile: profile) { showingDiagnostics = false }
        .environment(\.palette, p).buttonStyle(TauriButtonStyle())
    }
    .sheet(isPresented: $showingLog) {
      LogSheet(
        title: L10n.text("diag.title", ["name": profile.groupName]),
        load: { await model.connectionLog(profile) }, onClose: { showingLog = false }
      ).environment(\.palette, p).buttonStyle(TauriButtonStyle())
    }
    .sheet(isPresented: $editingRules) {
      RoutingRulesEditor(model: model, profile: profile) { editingRules = false }
        .environment(\.palette, p).buttonStyle(TauriButtonStyle())
    }
    .sheet(isPresented: $editingNetworks) {
      TunnelNetworksSheet(model: model, profile: profile) { editingNetworks = false }
        .environment(\.palette, p).buttonStyle(TauriButtonStyle())
    }
  }
  /// Compact per-set summary; the sets are edited in a full-size sheet.
  @ViewBuilder private var routingRules: some View {
    HStack {
      section("detail.domainRules")
      Spacer()
      Button(L10n.text("common.edit")) { editingRules = true }.buttonStyle(
        TauriButtonStyle(compact: true)
      ).padding(.top, 6)
    }
    ForEach(RoutingRulesEditor.sets, id: \.target) { set in
      let count = profile.rules(set.target).filter { !$0.hasPrefix("#") }.count
      HStack(spacing: 7) {
        Circle().fill(p[set.color]).frame(width: 7, height: 7)
        Text(L10n.text(set.title)).foregroundStyle(p.muted)
        Spacer()
        Text(L10n.text("rules.entryCount", ["count": String(count)]))
          .foregroundStyle(count == 0 ? p.muted : p.text)
      }.font(.system(size: 11.9)).padding(.vertical, 2)
    }
    if profile.privateLanDirect ?? false {
      Text(L10n.text("form.privateLanDirect")).font(.system(size: 10.92)).foregroundStyle(p.muted)
    }
    if let dns = profile.xrayDns, dns.serverCount + dns.hostCount > 0 {
      Text(
        L10n.text(
          "rules.dnsSummary",
          ["servers": String(dns.serverCount), "hosts": String(dns.hostCount)])
      ).font(.system(size: 10.92)).foregroundStyle(p.muted)
    }
  }
  @ViewBuilder private var tunnelConfig: some View {
    if let inspection = model.inspections[profile.id],
      profile.backend == "wireGuard" || profile.backend == "openVpn"
    {
      let wireGuard = profile.backend == "wireGuard"
      let flatEndpoints = wireGuard ? [] : inspection.endpoints
      let flatRoutes = wireGuard ? [] : inspection.osRoutes
      if !inspection.interfaceDetails.isEmpty || !inspection.peers.isEmpty
        || !flatEndpoints.isEmpty || !flatRoutes.isEmpty
      {
        section("detail.tunnelConfig")
        ForEach(Array(inspection.interfaceDetails.enumerated()), id: \.offset) { _, detail in
          row(Self.fieldKeys[detail.field] ?? "detail.tunnelConfig", detail.value)
        }
        if wireGuard {
          ForEach(Array(inspection.peers.enumerated()), id: \.offset) { index, peer in
            row(
              L10n.text("detail.peerN", ["n": String(index + 1)]), peer.endpoint?.label ?? "—",
              translate: false)
            ForEach(Array(peer.routes.enumerated()), id: \.offset) { _, route in
              bullet(route.destination)
            }
          }
        }
        ForEach(Array(flatEndpoints.enumerated()), id: \.offset) { _, endpoint in
          row("detail.peerEndpoint", endpoint.label)
        }
        ForEach(Array(flatRoutes.enumerated()), id: \.offset) { _, route in
          bullet(route.destination)
        }
      }
    }
  }
  @ViewBuilder private var endpoints: some View {
    if let subscription = profile.subscription,
      let endpoints = model.subscriptionEndpoints[profile.id]
    {
      HStack(spacing: 7) {
        section(L10n.text("detail.endpoints") + " · \(endpoints.count)", translate: false)
        Spacer()
        let pending = model.probing[profile.id]
        Button {
          Task { await model.measureDelays(profile) }
        } label: {
          HStack(spacing: 6) {
            if let pending {
              Spinner(size: 10)
              Text(
                L10n.text(
                  "native.pingProgress",
                  ["done": String(endpoints.count - pending.count), "total": String(endpoints.count)]))
            } else {
              Text(L10n.text("native.ping"))
            }
          }
        }.buttonStyle(TauriButtonStyle(compact: true))
          .disabled(pending != nil || !(model.runtime?.xrayInstalled ?? false))
          .help(L10n.text("detail.testAllTitle"))
        Button(L10n.text(model.refreshing.contains(profile.id) ? "detail.refreshing" : "detail.refreshSub")) {
          Task { await model.refreshSubscription(profile) }
        }.buttonStyle(TauriButtonStyle(compact: true)).disabled(
          model.refreshing.contains(profile.id) || model.busy)
      }.padding(.top, 6)
      autoRefreshRow(subscription)
      let busy = model.busy || model.pending.contains(profile.id)
      ForEach(Array(endpoints.enumerated()), id: \.offset) { index, endpoint in
        let active = index == subscription.activeIndex
        Button {
          Task { await model.switchEndpoint(profile, index: index) }
        } label: {
          HStack(spacing: 7) {
            Circle().fill(active ? p.accent : .clear).frame(width: 6, height: 6)
            Text(profile.serverLabel(endpoint.name)).font(
              .system(size: 11.9, weight: active ? .semibold : .regular)
            ).lineLimit(1)
            if let proto = endpoint.protocol {
              Text(proto).font(.system(size: 9.8, design: .monospaced)).foregroundStyle(p.muted)
                .padding(.horizontal, 4).padding(.vertical, 1)
                .overlay(RoundedRectangle(cornerRadius: 3).stroke(p.border, lineWidth: 1))
            }
            Spacer()
            if model.probing[profile.id]?.contains(index) ?? false {
              Spinner(size: 10)
            } else {
              delayBadge(model.delays[profile.id]?[index])
            }
          }.padding(.horizontal, 7).padding(.vertical, 4).background(
            active ? p["accent-dim"] : .clear, in: RoundedRectangle(cornerRadius: 5)
          ).contentShape(Rectangle())
        }.buttonStyle(.plain).disabled(active || busy)
          .help(L10n.text(active ? "detail.activeEndpoint" : "detail.switchEndpoint"))
      }
    }
  }
  @ViewBuilder private func autoRefreshRow(_ subscription: SubscriptionMeta) -> some View {
    HStack(spacing: 10) {
      Text(L10n.text("detail.autoRefresh")).foregroundStyle(p.muted)
      Spacer()
      Picker(
        L10n.text("detail.autoRefresh"),
        selection: Binding(
          get: { subscription.refreshIntervalMinutes ?? 0 },
          set: { value in
            Task { await model.setRefreshInterval(profile, minutes: value == 0 ? nil : value) }
          })
      ) {
        Text(L10n.text("common.off")).tag(UInt32(0))
        Text(L10n.text("detail.every15")).tag(UInt32(15))
        Text(L10n.text("detail.everyHour")).tag(UInt32(60))
        Text(L10n.text("detail.every6h")).tag(UInt32(360))
      }.labelsHidden().frame(width: 190).disabled(model.busy)
    }.font(.system(size: 11.9)).padding(.vertical, 2)
    let hints: [String] = [
      subscription.lastRefreshAtUnix.map {
        L10n.text("detail.lastChecked") + ": "
          + Date(timeIntervalSince1970: TimeInterval($0)).formatted(
            .dateTime.day().month().hour().minute()
              .locale(Locale(identifier: L10n.shared.language)))
      },
      subscription.updateIntervalHours.map {
        L10n.text("detail.providerInterval", ["hours": String($0)])
      },
    ].compactMap { $0 }
    if !hints.isEmpty || subscription.lastRefreshError != nil {
      HStack(spacing: 8) {
        Text(hints.joined(separator: " · ")).foregroundStyle(p.muted)
        if subscription.lastRefreshError != nil {
          Text(L10n.text("native.refreshFailed")).foregroundStyle(p["down"])
        }
      }.font(.system(size: 10.92)).padding(.bottom, 4)
    }
  }
  /// Delay readout: green under 300 ms, amber under 800 ms, red above or
  /// when the server did not answer; nothing until measured.
  @ViewBuilder private func delayBadge(_ value: UInt64??) -> some View {
    switch value {
    case .some(.some(let ms)):
      Text(L10n.text("native.ms", ["ms": String(ms)])).font(
        .system(size: 10.5, weight: .medium, design: .monospaced)
      ).foregroundStyle(p[ms < 300 ? "up" : ms < 800 ? "warn" : "down"])
    case .some(.none):
      Text(L10n.text("detail.unreachable")).font(.system(size: 10.5)).foregroundStyle(p["down"])
    case .none:
      EmptyView()
    }
  }
  static func usageText(_ usage: SubscriptionUsage) -> String {
    let format = { (bytes: UInt64) in
      ByteCountFormatter.string(fromByteCount: Int64(clamping: bytes), countStyle: .binary)
    }
    var text = format(usage.uploadBytes + usage.downloadBytes)
    text += " / " + (usage.totalBytes.map(format) ?? L10n.text("detail.unlimited"))
    if let expires = usage.expiresAtUnix {
      let date = Date(timeIntervalSince1970: TimeInterval(expires))
      text += " · " + L10n.text("native.until", [
        "date": date.formatted(.dateTime.day().month().year().locale(Locale(identifier: L10n.shared.language)))
      ])
    }
    return text
  }
  private static let fieldKeys: [String: String] = [
    "address": "detail.cfg.address", "dns": "detail.cfg.dns", "mtu": "detail.cfg.mtu",
    "listenPort": "detail.cfg.listenPort", "protocol": "detail.cfg.protocol",
    "device": "detail.cfg.device", "cipher": "detail.cfg.cipher",
    "authUserPass": "detail.cfg.authUserPass",
  ]
  private func statusLine(_ status: TunnelStatus?) -> String {
    switch status?.state {
    case "running":
      L10n.text(
        "detail.runningOn",
        ["iface": profile.needsHelper
          ? (status?.interfaceName ?? "tunnel")
          : profile.xraySocksPort.map { "127.0.0.1:\($0)" } ?? "tunnel"])
        + (model.activeServer(profile).map { " · \($0)" } ?? "")
        // Notices of a tunnel that works: "connecting", "IPv6 is not covered", …
        + (status?.message.map { " · " + L10n.text($0) } ?? "")
    case "failed": status?.message.map { L10n.text($0) } ?? L10n.text("detail.failed")
    default:
      model.canStart(profile) || profile.startsWithoutHelper || !model.canStartConnections
        ? L10n.text("detail.stopped") : L10n.text("native.helperRequired")
    }
  }
  /// Static routes: arm them while the interface is absent, or refuse.
  private var waitRow: some View {
    HStack {
      VStack(alignment: .leading, spacing: 2) {
        Text(L10n.text("native.static.wait")).foregroundStyle(p.muted)
        Text(L10n.text("native.static.waitHint")).font(.system(size: 10.08)).foregroundStyle(p.muted)
      }
      Spacer()
      Toggle(
        "",
        isOn: Binding(
          get: { profile.waitsForInterface },
          set: { value in Task { await model.setWaitForInterface(profile, enabled: value) } })
      ).toggleStyle(.switch).controlSize(.small).labelsHidden()
        .disabled(model.pending.contains(profile.id))
    }.font(.system(size: 11.9)).padding(.vertical, 5)
  }
  /// Starts this connection when the app launches.
  private var autoConnectRow: some View {
    HStack {
      Text(L10n.text("form.autoConnect")).foregroundStyle(p.muted)
      Spacer()
      Toggle(
        "",
        isOn: Binding(
          get: { profile.connectsOnLaunch },
          set: { value in Task { await model.setAutoConnect(profile, enabled: value) } })
      ).toggleStyle(.switch).controlSize(.small).labelsHidden()
        .disabled(model.pending.contains(profile.id))
    }.font(.system(size: 11.9)).padding(.vertical, 5)
  }
  /// Primary or secondary, and for a secondary one its networks.
  @ViewBuilder private var roleRows: some View {
    HStack {
      VStack(alignment: .leading, spacing: 2) {
        Text(L10n.text("native.role")).foregroundStyle(p.muted)
        Text(L10n.text("native.roleHint")).font(.system(size: 10.08)).foregroundStyle(p.muted)
      }
      Spacer()
      Picker(
        "",
        selection: Binding(
          get: { profile.isSecondary ? "secondary" : "primary" },
          set: { value in Task { await model.setTunnelRole(profile, role: value) } })
      ) {
        Text(L10n.text("native.rolePrimary")).tag("primary")
        Text(L10n.text("native.roleSecondary")).tag("secondary")
      }.pickerStyle(.segmented).labelsHidden().frame(width: 190)
        .disabled(model.pending.contains(profile.id))
    }.font(.system(size: 11.9)).padding(.vertical, 5)
    if profile.isSecondary {
      HStack(alignment: .top) {
        VStack(alignment: .leading, spacing: 2) {
          Text(L10n.text("native.networks")).foregroundStyle(p.muted)
          let networks = profile.tunnelNetworks ?? []
          Text(networks.isEmpty ? L10n.text("native.networksEmpty") : networks.joined(separator: ", "))
            .font(.system(size: 10.92, design: .monospaced))
            .foregroundStyle(networks.isEmpty ? p["warn"] : p.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        Spacer()
        Button(L10n.text("native.networksEdit")) { editingNetworks = true }
          .buttonStyle(TauriButtonStyle(compact: true))
      }.font(.system(size: 11.9)).padding(.vertical, 5)
    }
  }
  /// Loopback SOCKS proxy or a tunnel for the whole system.
  private var modePicker: some View {
    HStack {
      VStack(alignment: .leading, spacing: 2) {
        Text(L10n.text("native.tunnelMode")).foregroundStyle(p.muted)
        Text(L10n.text(model.helperServesTunnels ? "native.tunnelModeHint" : "native.tunnelModeNeedsHelper"))
          .font(.system(size: 10.08)).foregroundStyle(p.muted)
      }
      Spacer()
      Picker(
        "",
        selection: Binding(
          get: { profile.isTun ? "tun" : "socks" },
          set: { value in Task { await model.setXrayMode(profile, mode: value) } })
      ) {
        Text("SOCKS").tag("socks")
        Text("TUN").tag("tun")
      }.pickerStyle(.segmented).labelsHidden().frame(width: 130)
        .disabled(model.pending.contains(profile.id))
    }.font(.system(size: 11.9)).padding(.vertical, 5)
  }
  private func section(_ title: String, translate: Bool = true) -> some View {
    Text(translate ? L10n.text(title) : title).font(.system(size: 11.2, weight: .semibold))
      .foregroundStyle(p.secondary).padding(.top, 12).padding(.bottom, 3)
  }
  private func row(_ label: String, _ value: String, mono: Bool = true, translate: Bool = true)
    -> some View
  {
    HStack {
      Text(translate ? L10n.text(label) : label).foregroundStyle(p.muted)
      Spacer()
      Text(value).font(.system(size: 11.9, design: mono ? .monospaced : .default)).lineLimit(1)
        .textSelection(.enabled)
    }.font(.system(size: 11.9)).padding(.vertical, 3)
  }
  private func bullet(_ value: String) -> some View {
    Text("• " + value).font(.system(size: 11.9, design: .monospaced)).padding(.vertical, 1)
      .padding(.leading, 7)
  }
}
struct ConnectionModalView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let modal: ConnectionModal
  let onClose: () -> Void
  let onChoose: (ConnectionModal) -> Void
  var body: some View {
    switch modal {
    case .add:
      AppModal(title: "Add a connection", width: 480, onClose: onClose) {
        VStack(spacing: 7) {
          option(
            "ImportIcon", "Paste a link or import a file",
            "Subscription URL, share link, or a config file", .importConfig(nil))
          option(
            "WireGuardIcon", "WireGuard", "Enter tunnel keys, or open an existing .conf file.",
            .importConfig("wireGuard"))
          option(
            "OpenVpnIcon", "OpenVPN", "Use an existing .ovpn client config.",
            .importConfig("openVpn"))
          option(
            "XrayIcon", "Xray", "Import a share link, or an Xray JSON config.",
            .importConfig("xray"))
          option(
            "StaticRoutesIcon", "Static routes",
            "Route traffic through an existing interface, no tunnel.", .staticRoutes)
        }.padding(14)
      }
    case .importConfig(let backend):
      ImportConfigurationView(model: model, preferredBackend: backend, onClose: onClose)
    case .staticRoutes: StaticProfileView(model: model, onClose: onClose)
    }
  }
  private func option(
    _ icon: String, _ title: String, _ description: String, _ destination: ConnectionModal
  ) -> some View {
    Button {
      onChoose(destination)
    } label: {
      HStack(spacing: 10.5) {
        NativeIcon(name: icon, size: 18).foregroundStyle(p.accent).frame(width: 36, height: 36)
          .background(p["accent-dim"], in: Circle())
        VStack(alignment: .leading, spacing: 2) {
          Text(L10n.text(title)).font(.system(size: 12.6, weight: .semibold))
          Text(L10n.text(description)).font(.system(size: 10.92)).foregroundStyle(p.muted)
        }
        Spacer(minLength: 0)
      }.padding(10.5).background(p["bg-elev"], in: RoundedRectangle(cornerRadius: 12)).overlay(
        RoundedRectangle(cornerRadius: 12).stroke(p.border, lineWidth: 1))
    }.buttonStyle(.plain)
  }
}
struct ImportConfigurationView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let preferredBackend: String?
  let onClose: () -> Void
  @State private var tab = "Files"
  @State private var name = ""
  @State private var backend = "wireGuard"
  @State private var file: URL?
  @State private var shareLink = ""
  @State private var subscriptionURL = ""
  @State private var hwid = ""
  @AppStorage("autoHWID") private var autoHWID = true
  init(
    model: AppModel, preferredBackend: String?, onClose: @escaping () -> Void,
    initialTab: String? = nil
  ) {
    self.model = model
    self.preferredBackend = preferredBackend
    self.onClose = onClose
    _tab = State(initialValue: initialTab ?? (preferredBackend == "xray" ? "Link" : "Files"))
  }
  var body: some View {
    AppModal(title: "Import configurations", width: 520, onClose: onClose) {
      VStack(alignment: .leading, spacing: 10.5) {
        AppTabs(
          titles: ["Files", "Link", "Subscription", "WireGuard location"], selected: $tab
        )
        .disabled(model.busy)
        if tab == "Files" {
          Text(
            L10n.text("Import WireGuard (.conf), OpenVPN (.ovpn), or Xray (.json) configurations.")
          ).font(
            .system(size: 11.9)
          ).foregroundStyle(p.secondary)
          Button(L10n.text("Choose files…")) { chooseFile() }
          if let file {
            Text(file.lastPathComponent).font(.system(size: 11.9)).foregroundStyle(p.secondary)
            Text(L10n.text("Name")).font(.system(size: 11.9))
            AppInput(placeholder: "Connection name", text: $name)
            HStack {
              Text(L10n.text("Backend")).font(.system(size: 11.9))
              Spacer()
              Picker("Backend", selection: $backend) {
                Text(L10n.text("WireGuard")).tag("wireGuard")
                Text(L10n.text("OpenVPN")).tag("openVpn")
                Text(L10n.text("Xray")).tag("xray")
              }.labelsHidden().frame(width: 170)
            }
          }
          Text(L10n.text("A private, managed copy is stored locally. Import does not start a VPN."))
            .font(
              .system(size: 10.92)
            ).foregroundStyle(p.muted)
        } else if tab == "Link" {
          Text(
            L10n.text(
              "native.linkHint"
            )
          )
          .font(.system(size: 11.9)).foregroundStyle(p.secondary)
          Text(L10n.text("Share link")).font(.system(size: 11.9))
          AppInput(placeholder: "native.linkPlaceholder", text: $shareLink)
            .disabled(model.busy)
            .onChange(of: shareLink) { model.error = nil }
          Text(L10n.text("Connection name (optional)")).font(.system(size: 11.9))
          AppInput(placeholder: "Use the name from the link", text: $name).disabled(model.busy)
        } else if tab == "Subscription" {
          Text(
            L10n.text(
              "Import a subscription URL. Supported vless:// and hysteria2:// endpoints are grouped into a profile with an endpoint selector."
            )
          )
          .font(.system(size: 11.9)).foregroundStyle(p.secondary)
          Text(L10n.text("Subscription URL")).font(.system(size: 11.9))
          AppInput(placeholder: "https://example.com/sub", text: $subscriptionURL)
            .disabled(model.busy)
            .onChange(of: subscriptionURL) { model.error = nil }
          Text(L10n.text("HWID (X-HWID header, optional)")).font(.system(size: 11.9))
          HStack(spacing: 10.5) {
            AppInput(
              placeholder: autoHWID ? "native.hwidAutoPlaceholder" : "device-hwid", text: $hwid
            ).disabled(model.busy || autoHWID)
            Toggle(L10n.text("native.hwidAuto"), isOn: $autoHWID).toggleStyle(.checkbox)
              .font(.system(size: 11.9)).fixedSize().disabled(model.busy)
              .onChange(of: autoHWID) { _, enabled in if enabled { hwid = "" } }
          }
          Text(L10n.text("Connection name (optional)")).font(.system(size: 11.9))
          AppInput(placeholder: "Use the name from the link", text: $name).disabled(model.busy)
          Text(
            L10n.text(
              "Import does not start a VPN. Automatic subscription refresh is not available in this native version yet."
            )
          )
          .font(.system(size: 10.92)).foregroundStyle(p.muted)
        } else {
          AppEmptyState {
            Text(
              L10n.text(
                "Automatic discovery is not implemented on macOS yet. Use Files to choose your WireGuard configuration."
              ))
          }
        }
        if let error = model.error {
          Text(L10n.text(error)).foregroundStyle(p["down"]).font(.system(size: 11.9))
        }
        HStack {
          Spacer()
          Button(L10n.text("Cancel"), action: onClose)
          Button(
            model.busy
              ? (tab == "Subscription" ? L10n.text("Fetching…") : L10n.text("Importing…"))
              : (tab == "Subscription" ? L10n.text("Fetch subscription") : L10n.text("Import"))
          ) {
            Task {
              let imported: Bool
              let link = shareLink.trimmingCharacters(in: .whitespacesAndNewlines)
              if tab == "Link" && Self.isSubscriptionURL(link) {
                var generated = ""
                if autoHWID {
                  guard let value = await model.generateHWID() else { return }
                  generated = value
                }
                imported = await model.importSubscription(url: link, hwid: generated, name: name)
              } else if tab == "Link" {
                imported = await model.importShareLink(link, name: name)
              } else if tab == "Subscription" {
                if autoHWID {
                  guard let value = await model.generateHWID() else { return }
                  hwid = value
                }
                imported = await model.importSubscription(
                  url: subscriptionURL, hwid: hwid, name: name)
              } else if let file {
                imported = await model.importConfig(url: file, backend: backend, name: name)
              } else {
                imported = false
              }
              if imported {
                onClose()
                model.section = .connections
              }
            }
          }.buttonStyle(TauriButtonStyle(kind: .accent)).disabled(
            model.busy
              || (tab == "Link"
                ? shareLink.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                : tab == "Subscription"
                  ? subscriptionURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                  : tab != "Files" || file == nil
                    || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
          )
        }
      }.padding(14)
    }
    .dropDestination(for: URL.self) { urls, _ in
      guard let url = urls.first, url.isFileURL else { return false }
      use(url)
      return true
    }
    .onAppear {
      backend = preferredBackend ?? "wireGuard"
      model.error = nil
    }
  }
  private func chooseFile() {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    // Any file: configs often arrive as .txt or without an extension; the
    // backend picker and the shared analysis decide what is importable.
    panel.message = L10n.text("Import WireGuard (.conf), OpenVPN (.ovpn), or Xray (.json) configurations.")
    if panel.runModal() == .OK, let url = panel.url { use(url) }
  }
  static func isSubscriptionURL(_ text: String) -> Bool {
    let lower = text.lowercased()
    return lower.hasPrefix("https://") || lower.hasPrefix("http://")
  }
  private func use(_ url: URL) {
    tab = "Files"
    file = url
    if name.isEmpty { name = url.deletingPathExtension().lastPathComponent }
    backend =
      preferredBackend
      ?? (url.pathExtension == "ovpn"
        ? "openVpn" : url.pathExtension == "json" ? "xray" : "wireGuard")
  }
}
struct StaticProfileView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let onClose: () -> Void
  @State private var name = ""
  @State private var interface = ""
  @State private var cidrs = ""
  @State private var bypass = ""
  var body: some View {
    AppModal(title: "New connection", width: 620, onClose: onClose) {
      VStack(alignment: .leading, spacing: 10.5) {
        Text(L10n.text("Static routes")).font(.system(size: 13.3, weight: .semibold))
        Text(L10n.text("Name")).font(.system(size: 11.9))
        AppInput(placeholder: "Connection name", text: $name)
        Text(L10n.text("Interface")).font(.system(size: 11.9))
        AppInput(placeholder: "native.static.interfaceHint", text: $interface)
        Text(L10n.text("Routes")).font(.system(size: 13.3, weight: .semibold))
        TextEditor(text: $cidrs).font(.system(size: 11.9, design: .monospaced))
          .scrollContentBackground(.hidden).padding(7).frame(height: 120).background(
            p.input, in: RoundedRectangle(cornerRadius: 6)
          ).overlay(RoundedRectangle(cornerRadius: 6).stroke(p.border, lineWidth: 1))
          .accessibilityLabel(L10n.text("Bulk CIDRs"))
        Text(L10n.text("native.static.routesHint")).font(.system(size: 10.92))
          .foregroundStyle(p.muted)
        Text(L10n.text("native.static.bypass")).font(.system(size: 13.3, weight: .semibold))
        TextEditor(text: $bypass).font(.system(size: 11.9, design: .monospaced))
          .scrollContentBackground(.hidden).padding(7).frame(height: 54).background(
            p.input, in: RoundedRectangle(cornerRadius: 6)
          ).overlay(RoundedRectangle(cornerRadius: 6).stroke(p.border, lineWidth: 1))
          .accessibilityLabel(L10n.text("native.static.bypass"))
        Text(L10n.text("native.static.bypassHint")).font(.system(size: 10.92))
          .foregroundStyle(p.muted)
        if let error = model.error {
          Text(L10n.text(error)).font(.system(size: 11.9)).foregroundStyle(p["down"])
        }
        HStack {
          Spacer()
          Button(L10n.text("Cancel"), action: onClose)
          Button(L10n.text(model.busy ? "Saving…" : "Save")) {
            Task {
              if await model.createStatic(name: name, interface: interface, cidrs: cidrs, bypass: bypass) {
                onClose()
                model.section = .connections
              }
            }
          }.buttonStyle(TauriButtonStyle(kind: .accent)).disabled(
            model.busy
              || [name, cidrs].contains {
                $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
              })
        }
      }.padding(14)
    }
  }
}
struct InspectionView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let profile: Profile
  @Environment(\.dismiss) private var dismiss
  var body: some View {
    AppModal(
      title: L10n.text(
        "Configuration analysis — {name}", ["name": String(describing: profile.name)]), width: 650,
      onClose: dismiss.callAsFunction
    ) {
      ScrollView {
        VStack(alignment: .leading, spacing: 14) {
          if let inspection = model.inspection {
            AppHeading(title: "OS routes")
            if inspection.osRoutes.isEmpty {
              Text(L10n.text("No declared OS routes")).foregroundStyle(p.muted)
            }
            ForEach(Array(inspection.osRoutes.enumerated()), id: \.offset) { _, route in
              Text("\(route.destination) · \(route.source)").font(
                .system(size: 11.9, design: .monospaced))
            }
            if !inspection.internalRoutes.isEmpty {
              AppHeading(title: "Internal proxy routes")
              ForEach(Array(inspection.internalRoutes.enumerated()), id: \.offset) { _, route in
                Text("\(route.destination) · \(route.source)").font(
                  .system(size: 11.9, design: .monospaced))
              }
            }
            if !inspection.listeners.isEmpty {
              AppHeading(title: "Local listeners")
              ForEach(Array(inspection.listeners.enumerated()), id: \.offset) { _, listener in
                Text("\(listener.protocol.uppercased()) · \(listener.address):\(listener.port)")
                  .font(.system(size: 11.9, design: .monospaced))
              }
            }
            ForEach(inspection.warnings, id: \.self) { Text($0).foregroundStyle(p["virtual"]) }
            if !inspection.routeKnowledgeComplete {
              Text(L10n.text("Server-pushed routes are not known until connection"))
                .foregroundStyle(p.muted)
            }
          } else if let error = model.error {
            Text(L10n.text(error)).foregroundStyle(p["down"])
          } else {
            ProgressView(L10n.text("Analyzing configuration…"))
          }
        }.padding(14).frame(maxWidth: .infinity, alignment: .leading)
      }.frame(height: 420)
    }
  }
}

/// Full-size editor for the Xray rule sets (block → proxy → direct), split
/// DNS and domain strategy, with a Happ/Incy import and an offline checker.
struct RoutingRulesEditor: View {
  struct RuleSet { let target: String; let title: String; let color: String }
  static let sets = [
    RuleSet(target: "block", title: "rules.block", color: "down"),
    RuleSet(target: "proxy", title: "rules.proxy", color: "accent"),
    RuleSet(target: "direct", title: "rules.direct", color: "up"),
  ]
  private static let strategies = [
    ("", "rules.strategyDefault"), ("asIs", "AsIs"), ("ipIfNonMatch", "IPIfNonMatch"),
    ("ipOnDemand", "IPOnDemand"),
  ]
  private static let matchers = [
    ("", "rules.matcherDefault"), ("mph", "mph"), ("hybrid", "hybrid"), ("linear", "linear"),
  ]
  private static let queryStrategies = [
    ("", "rules.matcherDefault"), ("useIp", "UseIP"), ("useIpv4", "UseIPv4"), ("useIpv6", "UseIPv6"),
  ]
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  let profile: Profile
  let onClose: () -> Void
  @State private var selected = "proxy"
  @State private var options = RoutingOptions()
  @State private var importing = false
  @State private var happPayload = ""
  @State private var happWarnings: [String] = []
  @State private var testTarget = ""
  @State private var checking = false
  @State private var verdict: RouteCheckResult?

  private func text(_ target: String) -> Binding<String> {
    switch target {
    case "block": $options.block
    case "direct": $options.direct
    default: $options.proxy
    }
  }
  private func count(_ target: String) -> Int {
    text(target).wrappedValue.split(separator: "\n")
      .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty && !$0.hasPrefix("#") }.count
  }
  private func tab(_ id: String, title: String, color: String?, badge: String?) -> some View {
    Button {
      selected = id
    } label: {
      HStack(spacing: 6) {
        if let color { Circle().fill(p[color]).frame(width: 7, height: 7) }
        Text(L10n.text(title))
        if let badge { Text(badge).foregroundStyle(p.muted) }
      }.font(.system(size: 11.9, weight: selected == id ? .semibold : .regular))
        .padding(.horizontal, 10).padding(.vertical, 5)
        .background(selected == id ? p["bg-elev"] : .clear, in: RoundedRectangle(cornerRadius: 6))
    }.buttonStyle(.plain)
  }
  private func editor(_ binding: Binding<String>, height: CGFloat, label: String) -> some View {
    TextEditor(text: binding)
      .font(.system(size: 11.9, design: .monospaced)).scrollContentBackground(.hidden)
      .padding(7).frame(height: height)
      .background(p.input, in: RoundedRectangle(cornerRadius: 6))
      .overlay(RoundedRectangle(cornerRadius: 6).stroke(p.border, lineWidth: 1))
      .accessibilityLabel(L10n.text(label))
  }
  private func picker(_ title: String, _ value: Binding<String>, _ items: [(String, String)])
    -> some View
  {
    HStack {
      Text(L10n.text(title)).font(.system(size: 11.9))
      Spacer()
      Picker("", selection: value) {
        ForEach(items, id: \.0) { Text(L10n.text($0.1)).tag($0.0) }
      }.labelsHidden().frame(width: 190)
    }
  }
  private var dnsPane: some View {
    VStack(alignment: .leading, spacing: 8) {
      picker("rules.domainStrategy", $options.domainStrategy, Self.strategies)
      picker("rules.domainMatcher", $options.domainMatcher, Self.matchers)
      picker("native.queryStrategy", $options.queryStrategy, Self.queryStrategies)
      Text(L10n.text("rules.outboundDns")).font(.system(size: 11.9, weight: .semibold))
      editor($options.dnsServers, height: 110, label: "rules.outboundDns")
      Text(L10n.text("native.dnsServersHint")).font(.system(size: 10.92)).foregroundStyle(p.muted)
        .fixedSize(horizontal: false, vertical: true)
      Text(L10n.text("native.staticHosts")).font(.system(size: 11.9, weight: .semibold))
      editor($options.dnsHosts, height: 70, label: "native.staticHosts")
      Toggle(L10n.text("native.fakeDns"), isOn: $options.fakeDns).toggleStyle(.checkbox)
        .font(.system(size: 11.9))
      Text(L10n.text("form.geoHint")).font(.system(size: 10.92)).foregroundStyle(p.muted)
        .fixedSize(horizontal: false, vertical: true)
      AppInput(placeholder: "native.geo.geoip", text: $options.geoipUrl)
      AppInput(placeholder: "native.geo.geosite", text: $options.geositeUrl)
    }
  }
  private var checker: some View {
    VStack(alignment: .leading, spacing: 6) {
      HStack(spacing: 8) {
        TextField(L10n.text("rules.testPlaceholder"), text: $testTarget)
          .textFieldStyle(.roundedBorder).font(.system(size: 11.9, design: .monospaced))
          .onSubmit(runCheck)
        Button(L10n.text(checking ? "rules.testChecking" : "rules.testCheck"), action: runCheck)
          .disabled(checking || testTarget.trimmingCharacters(in: .whitespaces).isEmpty)
      }
      if let verdict {
        HStack(spacing: 6) {
          Circle().fill(p[Self.outboundColor(verdict.outbound)]).frame(width: 7, height: 7)
          Text(L10n.text(Self.outboundTitle(verdict.outbound))).fontWeight(.semibold)
          Text("· " + sourceText(verdict)).foregroundStyle(p.muted)
        }.font(.system(size: 11.9))
        if let selector = verdict.matchedSelector {
          Text(selector).font(.system(size: 10.92, design: .monospaced)).foregroundStyle(p.muted)
        }
        if verdict.certainty == "probable" {
          Text(L10n.text("rules.testProbable")).font(.system(size: 10.92)).foregroundStyle(p["warn"])
        }
        ForEach(verdict.notes, id: \.self) {
          Text($0).font(.system(size: 10.92)).foregroundStyle(p.muted)
        }
      }
    }
  }
  private static func outboundColor(_ outbound: String) -> String {
    switch outbound {
    case "block": "down"
    case "direct": "up"
    case "dns": "info"
    default: "accent"
    }
  }
  private static func outboundTitle(_ outbound: String) -> String {
    switch outbound {
    case "block": "rules.block"
    case "direct": "rules.direct"
    case "dns": "rules.outboundDns"
    default: "rules.proxy"
    }
  }
  private func sourceText(_ verdict: RouteCheckResult) -> String {
    switch verdict.source {
    case "dnsCapture": L10n.text("rules.srcDnsCapture")
    case "policy": L10n.text("rules.srcPolicy", ["index": String((verdict.policyIndex ?? 0) + 1)])
    case "resolverPin": L10n.text("rules.srcResolverPin")
    case "multicast": L10n.text("rules.srcMulticast")
    case "privateLan": L10n.text("rules.srcPrivateLan")
    default: L10n.text("rules.srcDefault")
    }
  }
  private func runCheck() {
    let target = testTarget.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !target.isEmpty, !checking else { return }
    model.error = nil
    checking = true
    Task {
      verdict = await model.checkRoute(target, options: options)
      checking = false
    }
  }
  private var happPane: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text(L10n.text("rules.happHint")).font(.system(size: 10.92)).foregroundStyle(p.muted)
      editor($happPayload, height: 120, label: "rules.importHapp")
      HStack {
        Spacer()
        Button(L10n.text("rules.back")) { importing = false }
        Button(L10n.text("rules.happApply")) {
          Task {
            guard let happ = await model.parseHappRouting(happPayload) else { return }
            options.apply(happ)
            happWarnings = happ.warnings
            happPayload = ""
            importing = false
          }
        }.buttonStyle(TauriButtonStyle(kind: .accent))
          .disabled(happPayload.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
      }
    }
  }
  var body: some View {
    AppModal(title: "detail.domainRules", width: 720, onClose: onClose) {
      VStack(alignment: .leading, spacing: 10.5) {
        if importing {
          happPane
        } else {
          HStack(spacing: 6) {
            ForEach(Self.sets, id: \.target) { set in
              tab(set.target, title: set.title, color: set.color, badge: "\(count(set.target))")
            }
            tab("dns", title: "DNS", color: nil, badge: nil)
            Spacer()
            Button(L10n.text("rules.importHapp")) {
              model.error = nil
              importing = true
            }.font(.system(size: 11.9))
          }
          if selected == "dns" {
            dnsPane
          } else {
            editor(text(selected), height: 300, label: "detail.domainRules")
            Text(L10n.text("form.rulesHint")).font(.system(size: 10.92)).foregroundStyle(p.muted)
              .fixedSize(horizontal: false, vertical: true)
            Toggle(L10n.text("form.privateLanDirect"), isOn: $options.privateLanDirect)
              .toggleStyle(.checkbox).font(.system(size: 11.9))
          }
          Divider()
          checker
          ForEach(happWarnings, id: \.self) {
            Text($0).font(.system(size: 10.92)).foregroundStyle(p["warn"])
          }
        }
        if let error = model.error {
          Text(L10n.text(error)).foregroundStyle(p["down"]).font(.system(size: 11.9))
        }
        if !importing {
          HStack {
            Spacer()
            Button(L10n.text("Cancel"), action: onClose)
            Button(L10n.text("Save")) {
              Task { if await model.setRoutingRules(profile, options: options) { onClose() } }
            }.buttonStyle(TauriButtonStyle(kind: .accent)).disabled(model.busy)
          }
        }
      }.padding(14)
    }
    .onAppear {
      model.error = nil
      options.block = profile.rules("block").joined(separator: "\n")
      options.proxy = profile.rules("proxy").joined(separator: "\n")
      options.direct = profile.rules("direct").joined(separator: "\n")
      options.privateLanDirect = profile.privateLanDirect ?? false
      Task { if let loaded = await model.routingOptions(profile) { options = loaded } }
    }
  }
}
