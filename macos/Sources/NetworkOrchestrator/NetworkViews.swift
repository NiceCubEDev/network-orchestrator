import ServiceManagement
import SwiftUI

private let categoryOrder = ["physical", "vpn", "virtual", "system", "tunnel", "filter"]
private func categoryLabel(_ value: String) -> String {
  switch value {
  case "physical": "Physical"
  case "vpn": "VPN"
  case "virtual": "Virtual"
  case "system": "System interfaces"
  case "tunnel": "Tunnels"
  default: "Filters"
  }
}
private func categoryDescription(_ value: String) -> String {
  switch value {
  case "physical": "Physical network adapters"
  case "vpn": "VPN tunnel interfaces"
  case "virtual": "Virtual network adapters"
  case "system": "System and loopback interfaces"
  case "tunnel": "IP tunnels"
  default: "Network filter interfaces"
  }
}

struct NetworkView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State private var search = ""
  @State private var state = "All"
  @State private var categories = Set(["physical", "vpn", "virtual", "system"])
  @State private var preset = "Main adapters"
  @State private var collapsed = Set<String>()
  @State private var selected: NetworkInterface?
  @State private var confirmingOff = false
  private var interfaces: [NetworkInterface] { model.snapshot?.interfaces ?? [] }
  private var filtered: [NetworkInterface] {
    interfaces.filter {
      categories.contains($0.category) && (state == "All" || $0.state == state.lowercased())
        && (search.isEmpty || $0.friendlyName.localizedCaseInsensitiveContains(search)
          || $0.addresses.contains { $0.address.contains(search) })
    }
  }
  @State private var tab = "Adapters"
  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      AppHeading(title: "Network")
      AppTabs(titles: ["Adapters", "DNS"], selected: $tab)
      if tab == "DNS" { DnsView(model: model) } else { adapters }
    }
  }
  @ViewBuilder private var adapters: some View {
    VStack(alignment: .leading, spacing: 0) {
      HStack(spacing: 7) {
        AppInput(placeholder: "Search by name, MAC, address…", text: $search)
        AppSelect(
          label: "Adapter preset", selection: $preset,
          options: [
            ("Main adapters", "Main"), ("All adapters", "All interfaces"),
            ("OS internal", "OS-internal"),
          ]
        ).frame(width: 135)
          .onChange(of: preset) { _, value in
            categories = Set(
              value == "All adapters"
                ? categoryOrder
                : value == "OS internal"
                  ? ["tunnel", "filter"] : ["physical", "vpn", "virtual", "system"])
          }
        HStack(spacing: 2) {
          ForEach(["All", "Up", "Down"], id: \.self) { title in
            Button {
              state = title
            } label: {
              Text(L10n.text(title)).font(.system(size: 11.2)).foregroundStyle(p.text).padding(
                .horizontal, 12
              )
              .padding(.vertical, 4).background(
                state == title ? p.border : .clear, in: RoundedRectangle(cornerRadius: 4))
            }.buttonStyle(.plain)
          }
        }.padding(2).background(p.input, in: RoundedRectangle(cornerRadius: 6)).overlay(
          RoundedRectangle(cornerRadius: 6).stroke(p.border, lineWidth: 1))
      }.padding(.bottom, 7)
      HStack(spacing: 7) {
        ForEach(categoryOrder, id: \.self) { category in
          let count = interfaces.filter { $0.category == category }.count
          if count > 0 {
            Button {
              if !categories.insert(category).inserted { categories.remove(category) }
            } label: {
              HStack(spacing: 6) {
                NativeIcon(name: NativeIcon.category(category), size: 14)
                Text(L10n.text(categoryLabel(category)))
                Text("\(count)").font(.system(size: 9.8, weight: .semibold)).frame(
                  minWidth: 18, minHeight: 18
                ).background(categories.contains(category) ? p.accent : p.border, in: Capsule())
                  .foregroundStyle(categories.contains(category) ? .white : p.secondary)
              }
              .font(.system(size: 10.92)).foregroundStyle(
                categories.contains(category) ? p.text : p.muted
              ).padding(.horizontal, 10).padding(.vertical, 4).background(p.card, in: Capsule())
              .overlay(
                Capsule().stroke(
                  categories.contains(category) ? p.accent : p.border, lineWidth: 1))
            }.buttonStyle(.plain)
          }
        }
        Spacer(minLength: 0)
      }.padding(.bottom, 14)
      if let error = model.snapshot?.networkError {
        Text(L10n.text(error)).foregroundStyle(p["down"]).padding(.bottom, 14)
      }
      if filtered.isEmpty {
        AppEmptyState { Text(L10n.text("No interfaces match the current filters.")) }
      }
      ForEach(categoryOrder, id: \.self) { category in
        let rows = filtered.filter { $0.category == category }
        if !rows.isEmpty {
          VStack(alignment: .leading, spacing: 0) {
            Button {
              if !collapsed.insert(category).inserted { collapsed.remove(category) }
            } label: {
              HStack(spacing: 7) {
                NativeIcon(name: "ChevronIcon", size: 12).rotationEffect(
                  .degrees(collapsed.contains(category) ? 0 : 180))
                NativeIcon(name: NativeIcon.category(category), size: 14)
                Text(L10n.text(categoryLabel(category))).font(
                  .system(size: 11.2, weight: .semibold))
                Text("· \(rows.count)").font(.system(size: 10.08)).foregroundStyle(p.muted)
                Spacer()
                Text(L10n.text(categoryDescription(category))).font(.system(size: 10.5))
                  .foregroundStyle(p.muted)
              }.foregroundStyle(p.secondary).padding(.horizontal, 8).padding(.vertical, 5)
                .background(p["bg-elev"], in: RoundedRectangle(cornerRadius: 4))
                .contentShape(Rectangle())
            }.buttonStyle(.plain).padding(.bottom, 4)
            if !collapsed.contains(category) {
              ForEach(rows) { interface in
                Button {
                  selected = interface
                } label: {
                  InterfaceRow(interface: interface)
                }.buttonStyle(.plain)
              }
            }
          }.padding(.bottom, 14)
        }
      }
    }
    .sheet(item: $selected) { interface in
      AppModal(
        title: interface.friendlyName, width: 620, onClose: { selected = nil },
        translatesTitle: false
      ) {
        ScrollView {
          VStack(alignment: .leading, spacing: 14) {
            InterfaceCard(interface: interface)
            if model.canSwitch(interface) {
              HStack {
                Spacer()
                Button(
                  L10n.text(interface.state == "up" ? "native.link.turnOff" : "native.link.turnOn")
                ) {
                  if interface.state == "up" {
                    confirmingOff = true
                  } else {
                    Task { await switchInterface(interface, up: true) }
                  }
                }.disabled(model.switchingInterface)
              }
            }
            AppHeading(title: "Routes")
            Text(
              L10n.text(
                "{value0} system routes",
                [
                  "value0": String(
                    describing: model.snapshot?.routes.filter {
                      $0.interfaceIndex == interface.ifIndex
                    }.count ?? 0)
                ])
            ).foregroundStyle(p.secondary)
            RouteRows(
              routes: model.snapshot?.routes.filter { $0.interfaceIndex == interface.ifIndex } ?? []
            )
          }.padding(14)
        }.frame(height: 520)
      }.environment(\.palette, p)
        // On the sheet itself: an alert of the parent would sit behind it.
        .alert(
          L10n.text("native.link.offTitle"), isPresented: $confirmingOff, presenting: selected
        ) { interface in
          Button(L10n.text("native.link.turnOff"), role: .destructive) {
            Task { await switchInterface(interface, up: false) }
          }
          Button(L10n.text("common.cancel"), role: .cancel) {}
        } message: { interface in
          Text(L10n.text(model.switchOffWarning(interface), ["name": interface.friendlyName]))
        }
    }
  }
}
extension NetworkView {
  /// Switches the interface and shows its new state in the open sheet.
  fileprivate func switchInterface(_ interface: NetworkInterface, up: Bool) async {
    guard await model.setInterfaceState(interface, up: up) else { return }
    selected = model.snapshot?.interfaces.first { $0.ifIndex == interface.ifIndex }
  }
}
struct InterfaceCard: View {
  @Environment(\.palette) private var p
  let interface: NetworkInterface
  var body: some View {
    AppCard {
      VStack(alignment: .leading, spacing: 10.5) {
        HStack(spacing: 7) {
          NativeIcon(name: NativeIcon.category(interface.category), size: 18)
          Text(interface.friendlyName).font(.system(size: 14, weight: .semibold)).lineLimit(1)
          Spacer(minLength: 0)
          AppBadge(
            text: interface.physical ? "Physical" : "Virtual",
            color: interface.physical ? "physical" : "virtual")
          AppBadge(
            text: interface.state,
            color: interface.state == "up" ? "up" : interface.state == "down" ? "down" : "unknown")
        }
        Text(
          [
            interface.kind.label,
            interface.mtu.map { L10n.text("MTU: {value0}", ["value0": String(describing: $0)]) },
            interface.linkSpeedMbps.map {
              L10n.text("{value0} Mbps", ["value0": String(describing: $0)])
            },
          ].compactMap { $0 }.joined(separator: "   ")
        ).font(.system(size: 10.92)).foregroundStyle(p.muted)
        if !interface.description.isEmpty { row("Driver", interface.description) }
        if let mac = interface.mac { row("MAC", mac) }
        if let gateway = interface.gateway { row("Gateway", gateway) }
        if let gateway = interface.ipv6Gateway { row("IPv6 gateway", gateway) }
        if !interface.addresses.isEmpty {
          VStack(alignment: .leading, spacing: 4) {
            Text(L10n.text("ADDRESSES")).font(.system(size: 9.8, weight: .semibold))
              .foregroundStyle(p.muted)
            ForEach(Array(interface.addresses.enumerated()), id: \.offset) { _, addr in
              HStack(spacing: 3.5) {
                Text("•  \(addr.address)/\(addr.prefixLen)").font(
                  .system(size: 11.9, design: .monospaced))
                Text(addr.family).font(.system(size: 9.1)).foregroundStyle(p.muted).padding(
                  .horizontal, 4
                ).padding(.vertical, 1).background(p.border, in: RoundedRectangle(cornerRadius: 6))
              }
            }
          }
        }
        if !interface.dnsServers.isEmpty {
          row("DNS", interface.dnsServers.joined(separator: ", "))
        }
        if let suffix = interface.dnsSuffix { row("DNS suffix", suffix) }
      }
    }
  }
  private func row(_ title: String, _ value: String) -> some View {
    HStack(alignment: .top, spacing: 7) {
      Text(L10n.text(title)).foregroundStyle(p.muted)
      Spacer(minLength: 0)
      Text(value).font(.system(size: 11.9, design: .monospaced)).multilineTextAlignment(.trailing)
    }.font(.system(size: 11.9))
  }
}

enum RouteTab: String, CaseIterable {
  case overview = "Overview"
  case interfaces = "By interface"
  case flow = "Traffic flow"
  case tree = "Tree"
  case table = "Raw table"
  case lookup = "Lookup"
  case user = "My routing settings"
  case intents = "routes.intents"
  case conditions = "cond.title"
}
struct RoutesView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State private var tab: String
  init(model: AppModel, initialTab: RouteTab = .overview) {
    self.model = model
    _tab = State(initialValue: initialTab.rawValue)
  }
  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      AppHeading(title: "Routes")
      AppTabs(titles: RouteTab.allCases.map(\.rawValue), selected: $tab)
      if let error = model.snapshot?.networkError {
        Text(L10n.text(error)).foregroundStyle(p["down"]).padding(.bottom, 14)
      }
      switch RouteTab(rawValue: tab) ?? .overview {
      case .overview: RouteOverview(model: model)
      case .interfaces: RoutesByInterface(model: model)
      case .flow: TrafficFlowView(model: model)
      case .tree: RouteTreeView(model: model)
      case .table:
        VStack(alignment: .leading, spacing: 0) {
          AppHeading(title: "Routes")
          RouteRows(routes: model.snapshot?.routes ?? [])
        }
        case .lookup: RouteLookupView(model: model)
        case .user: UserRoutingView(model: model)
        case .intents: IntentsView(model: model)
        case .conditions: ConditionsView(model: model)
      }
    }.frame(minHeight: 300, alignment: .topLeading)
  }
}
struct RouteOverview: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State private var drill: String?
  private var predicted: [PlannedRoute] { model.snapshot?.routeMap.predicted ?? [] }
  private var routes: [Route] { model.snapshot?.routes ?? [] }
  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      LazyVGrid(columns: [GridItem(.adaptive(minimum: 160), spacing: 10.5)], spacing: 10.5) {
        summary(
          "\(predicted.filter(\.active).count)", "Active routes",
          L10n.text("{count} total predicted", ["count": String(describing: predicted.count)]),
          "owners")
        summary("\(routes.count)", "OS routes", "in effective table", nil)
        summary(
          "\(model.snapshot?.routeMap.diffs.count ?? 0)", "Conflicts",
          L10n.text(
            "{value0} warnings",
            ["value0": String(describing: model.snapshot?.routeMap.warnings.count ?? 0)]),
          "conflicts")
        summary(
          "\(Set(routes.map(\.interfaceName)+predicted.compactMap(\.interfaceName)).count)",
          "Interfaces",
          L10n.text(
            "{count} profiles",
            ["count": String(describing: Set(predicted.map(\.ownerProfileId)).count)]), "interfaces"
        )
      }
      if drill == "conflicts" {
        AppCard {
          VStack(alignment: .leading, spacing: 10.5) {
            Text(L10n.text("Conflicts & issues")).font(.system(size: 13.3, weight: .semibold))
            if model.snapshot?.routeMap.diffs.isEmpty ?? true,
              model.snapshot?.routeMap.warnings.isEmpty ?? true
            {
              AppEmptyState { Text(L10n.text("No conflicts detected.")) }
            }
            ForEach(Array((model.snapshot?.routeMap.diffs ?? []).enumerated()), id: \.offset) {
              _, diff in
              Text("\(diff.kind) · \(diff.destination) · \(diff.message)").font(.system(size: 11.9))
                .foregroundStyle(p["down"])
            }
            ForEach(model.snapshot?.routeMap.warnings ?? [], id: \.self) {
              Text($0).foregroundStyle(p["virtual"])
            }
          }
        }
      } else if drill == "owners" {
        RouteTreeView(model: model, defaultsToInactive: true)
      } else if drill == "interfaces" {
        RoutesByInterface(model: model, showsSystem: true)
      } else {
        Text(L10n.text("Click a summary card to drill down into details.")).font(
          .system(size: 11.9)
        )
        .foregroundStyle(p.muted).padding(.vertical, 14)
      }
    }
  }
  private func summary(_ number: String, _ title: String, _ sub: String, _ target: String?)
    -> some View
  {
    Button {
      if let target { drill = drill == target ? nil : target }
    } label: {
      AppCard {
        VStack(alignment: .leading, spacing: 2) {
          Text(number).font(.system(size: 24.5, weight: .bold)).tracking(-0.49)
          Text(L10n.text(title)).font(.system(size: 11.2, weight: .medium)).foregroundStyle(
            p.secondary)
          Text(L10n.text(sub)).font(.system(size: 10.08)).foregroundStyle(p.muted)
        }
      }
    }.buttonStyle(.plain)
  }
}
struct RouteRows: View {
  @Environment(\.palette) private var p
  let routes: [Route]
  var body: some View {
    VStack(spacing: 0) {
      tableRow(["Destination", "Prefix", "Gateway", "Interface", "Metric"], header: true)
      LazyVStack(spacing: 0) {
        ForEach(Array(routes.enumerated()), id: \.offset) { _, route in
          tableRow(
            [
              route.destination, "/\(route.prefixLen)", route.gateway ?? "—", route.interfaceName,
              "—",
            ], header: false)
        }
      }
      if routes.isEmpty { AppEmptyState { Text(L10n.text("No routes found.")) } }
    }.help(L10n.text("Darwin does not expose comparable metrics through the shared reader."))
  }
  private func tableRow(_ cells: [String], header: Bool) -> some View {
    HStack(spacing: 0) {
      ForEach(Array(cells.enumerated()), id: \.offset) { index, value in
        Text(header ? L10n.text(value) : value).font(
          .system(
            size: 11.9, weight: header ? .semibold : .regular,
            design: header ? .default : .monospaced)
        ).foregroundStyle(header ? p.secondary : p.text).frame(
          maxWidth: .infinity, alignment: .leading
        ).padding(.horizontal, 10.5).padding(.vertical, 7).lineLimit(1).minimumScaleFactor(0.7)
      }
    }.background(header ? p.card : .clear).overlay(alignment: .bottom) {
      Rectangle().fill(p.border).frame(height: 1)
    }
  }
}
struct RoutesByInterface: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  var showsSystem = false
  @State private var filter = ""
  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      AppInput(placeholder: "Filter by destination or owner…", text: $filter)
      if !showsSystem {
        FlowLayout {
          ForEach(model.snapshot?.profiles ?? []) { profile in
            HStack(spacing: 6) {
              Circle().fill(p.accent).frame(width: 8, height: 8)
              Text(profile.name).font(.system(size: 10.92)).foregroundStyle(p.secondary)
            }
          }
        }
      }
      LazyVGrid(
        columns: [GridItem(.adaptive(minimum: 290), spacing: 14)], alignment: .leading, spacing: 14
      ) {
        ForEach(groupNames, id: \.self) { name in
          let system = (model.snapshot?.routes ?? []).filter {
            $0.interfaceName == name
              && (filter.isEmpty || name.localizedCaseInsensitiveContains(filter)
                || $0.cidr.contains(filter))
          }
          let planned = (model.snapshot?.routeMap.predicted ?? []).filter {
            ($0.interfaceName ?? "auto") == name
              && (filter.isEmpty || $0.ownerName.localizedCaseInsensitiveContains(filter)
                || $0.destination.contains(filter))
          }
          let destinations = showsSystem ? system.map(\.cidr) : planned.map(\.destination)
          if !destinations.isEmpty {
            AppCard {
              VStack(alignment: .leading, spacing: 10.5) {
                HStack {
                  Text(name).font(.system(size: 13.3, weight: .semibold))
                  Spacer()
                  Text(
                    showsSystem
                      ? L10n.text("{count} routes", ["count": String(describing: system.count)])
                      : "\(planned.filter(\.active).count)/\(planned.count)"
                  ).font(.system(size: 10.92)).foregroundStyle(p.muted)
                }
                RouteChips(destinations: destinations, active: showsSystem)
              }
            }
          }
        }
      }
    }
  }
  private var groupNames: [String] {
    Array(
      Set(
        showsSystem
          ? model.snapshot?.routes.map(\.interfaceName) ?? []
          : model.snapshot?.routeMap.predicted.map { $0.interfaceName ?? "auto" } ?? [])
    ).sorted()
  }
}
struct RouteChips: View {
  @Environment(\.palette) private var p
  let destinations: [String]
  var active = false
  var body: some View {
    FlowLayout {
      ForEach(Array(destinations.enumerated()), id: \.offset) { _, value in
        Text(value).font(.system(size: 10.92, design: .monospaced)).foregroundStyle(
          active ? p["up"] : p.secondary
        ).padding(.horizontal, 7).padding(.vertical, 3.5).background(
          active ? p["up-bg"] : p["bg-elev"], in: RoundedRectangle(cornerRadius: 6)
        ).overlay(
          RoundedRectangle(cornerRadius: 6).stroke(active ? p["up-border"] : p.border, lineWidth: 1)
        ).textSelection(.enabled)
      }
    }
  }
}
struct RouteTreeView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  var defaultsToInactive = false
  @State private var includeInactive = false
  @State private var filter = ""
  @State private var collapsed = Set<String>()
  private var planned: [PlannedRoute] {
    (model.snapshot?.routeMap.predicted ?? []).filter {
      (includeInactive || defaultsToInactive || $0.active)
        && (filter.isEmpty || $0.destination.contains(filter)
          || $0.ownerName.localizedCaseInsensitiveContains(filter))
    }
  }
  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      HStack {
        AppHeading(title: "Route map")
        Toggle(L10n.text("Include stopped profiles"), isOn: $includeInactive).toggleStyle(.checkbox)
          .font(
            .system(size: 11.9)
          ).fixedSize()
      }
      AppInput(
        placeholder: "Filter by destination or owner (e.g. 10.0.0.0/8, work-vpn)", text: $filter)
      ForEach(model.snapshot?.routeMap.warnings ?? [], id: \.self) {
        Text($0).foregroundStyle(p["virtual"])
      }
      Text(L10n.text("Predicted routes")).font(.system(size: 16.38, weight: .bold))
      if planned.isEmpty { Text(L10n.text("No predicted routes.")).foregroundStyle(p.secondary) }
      ForEach(Array(Set(planned.map { $0.interfaceName ?? "auto" })).sorted(), id: \.self) { name in
        let routes = planned.filter { ($0.interfaceName ?? "auto") == name }
        group(name, name == "auto" ? "auto interface" : name, routes.count) {
          DesignTable(
            headers: ["Destination", "Owner", "Source", "Metric", "State"],
            rows: routes.map {
              [
                $0.destination, $0.ownerName, $0.source, $0.metric.map(String.init) ?? "auto",
                $0.active ? "active" : "stopped",
              ]
            })
        }
      }
      Text(L10n.text("Differences")).font(.system(size: 16.38, weight: .bold))
      if model.snapshot?.routeMap.diffs.isEmpty ?? true {
        Text(L10n.text("No active route differences. Saved native profiles are stopped.")).font(
          .system(size: 11.9)
        ).foregroundStyle(p["up"])
      }
      ForEach(Array((model.snapshot?.routeMap.diffs ?? []).enumerated()), id: \.offset) { _, diff in
        Text(diff.message).foregroundStyle(p["down"])
      }
      Text(L10n.text("Effective routes")).font(.system(size: 16.38, weight: .bold))
      ForEach(Array(Set(model.snapshot?.routes.map(\.interfaceName) ?? [])).sorted(), id: \.self) {
        name in
        let routes = (model.snapshot?.routes ?? []).filter {
          $0.interfaceName == name && (filter.isEmpty || $0.cidr.contains(filter))
        }
        group("effective-" + name, name, routes.count) {
          DesignTable(headers: ["Destination", "Metric"], rows: routes.map { [$0.cidr, "—"] })
        }
      }
    }
  }
  private func group<C: View>(
    _ id: String, _ title: String, _ count: Int, @ViewBuilder content: () -> C
  ) -> some View {
    AppCard(padding: 0) {
      VStack(spacing: 0) {
        Button {
          if !collapsed.insert(id).inserted { collapsed.remove(id) }
        } label: {
          HStack(spacing: 7) {
            Text(collapsed.contains(id) ? "▸" : "▾")
            Text(L10n.text(title)).fontWeight(.semibold)
            Text("\(count)").font(.system(size: 10.08)).padding(.horizontal, 7).padding(
              .vertical, 1
            ).background(p.border, in: Capsule())
            Spacer()
          }.font(.system(size: 11.9)).foregroundStyle(p.secondary).padding(.horizontal, 14).padding(
            .vertical, 10.5
          ).background(p["bg-elev"])
        }.buttonStyle(.plain)
        if !collapsed.contains(id) { content() }
      }
    }
  }
}
struct TrafficFlowView: View {
  @Bindable var model: AppModel
  var body: some View {
    AppEmptyState { Text(L10n.text("No active routes to visualize. Connect a profile first.")) }
  }
}
struct RouteLookupView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      AppHeading(title: "Route Lookup")
      HStack(spacing: 7) {
        AppInput(placeholder: "Enter IPv4 or IPv6 address…", text: $model.lookupDestination)
          .onSubmit { Task { await model.lookupRoute() } }
        Button(L10n.text("Lookup")) { Task { await model.lookupRoute() } }.disabled(
          model.lookupDestination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
      }
      if let lookup = model.lookup {
        AppCard {
          VStack(alignment: .leading, spacing: 10.5) {
            Text(
              L10n.text(
                "Destination:  {destination}",
                ["destination": String(describing: lookup.destination)]))
            Text(
              L10n.text(
                "Interface:  {interfaceName}",
                ["interfaceName": String(describing: lookup.interfaceName)]))
            Text(L10n.text("Matched route")).font(.system(size: 10.92, weight: .semibold))
              .foregroundStyle(
                p.muted)
            RouteRows(routes: [lookup.matchedRoute])
          }.font(.system(size: 11.9))
        }
      }
      Text(
        L10n.text(
          "Table preview uses longest-prefix match. Interface-scoped macOS policy can affect the kernel’s route choice."
        )
      ).font(.system(size: 10.92)).foregroundStyle(p.muted)
    }
  }
}
struct SettingsView: View {
  @Environment(\.palette) private var p
  @Bindable var model: AppModel
  @State private var showingImportLog = false
  @State private var loginItemEnabled = false
  @AppStorage("showMenuBar") private var showMenuBar = true
  @AppStorage("appearance") private var appearance = "system"
  @Bindable private var localizer = L10n.shared
  var body: some View {
    VStack(alignment: .leading, spacing: 21) {
      AppHeading(title: "Settings").padding(.bottom, -14)
      settingsGroup("Appearance") {
        HStack {
          settingText("Theme", "Use system appearance, light or dark.")
          Spacer()
          AppSelect(
            label: "Theme", selection: $appearance,
            options: [("system", "System"), ("light", "Light"), ("dark", "Dark")]
          ).frame(width: 150)
        }.padding(.horizontal, 14).padding(.vertical, 10.5)
        Rectangle().fill(p.border).frame(height: 1)
        HStack {
          settingText("Language", "Choose the interface language.")
          Spacer()
          AppSelect(label: "Language", selection: $localizer.preference, options: localizer.options)
            .frame(width: 150)
        }.padding(.horizontal, 14).padding(.vertical, 10.5)
      }
      settingsGroup("settings.appMode") {
        HStack {
          settingText("settings.appMode", "settings.appModeSub")
          Spacer()
          AppSelect(
            label: "settings.appMode",
            selection: Binding(
              get: { model.appMode.rawValue },
              set: { value in
                guard let mode = AppMode(rawValue: value) else { return }
                Task { await model.setAppMode(mode) }
              }),
            options: AppMode.allCases.map { (value: $0.rawValue, title: $0.titleKey) }
          ).frame(width: 150)
        }.padding(.horizontal, 14).padding(.vertical, 10.5)
      }
      settingsGroup("Backend & dependencies") {
        VStack(alignment: .leading, spacing: 10.5) {
          HStack {
            Text(L10n.text("Backend prerequisites")).font(.system(size: 12.6, weight: .semibold))
            Spacer()
            Button(L10n.text("Refresh")) { Task { await model.refresh() } }.disabled(model.busy)
          }
          ForEach(["WireGuard", "OpenVPN", "Xray"], id: \.self) { backend in
            HStack(spacing: 10.5) {
              Text(backend).font(.system(size: 11.48, weight: .semibold)).frame(
                width: 77, alignment: .leading)
              if backend == "Xray", model.canStartConnections, let runtime = model.runtime {
                AppBadge(
                  text: runtime.xrayInstalled ? "native.installed" : "statusbar.state.absent",
                  color: runtime.xrayInstalled ? "up" : "unknown")
                Text(L10n.text("native.xraySettings", ["version": runtime.xrayVersion])).font(
                  .system(size: 11.48)
                ).foregroundStyle(p.secondary)
                Spacer()
                if !runtime.xrayInstalled {
                  Button(L10n.text(model.installingXray ? "native.installing" : "native.installXray"))
                  { Task { await model.installXray() } }.disabled(model.installingXray)
                }
              } else if backend == "WireGuard" || backend == "OpenVPN" {
                let serves = model.helperOffers(
                  backend == "WireGuard" ? "wireguard.connect" : "openvpn.connect")
                AppBadge(
                  text: serves ? "native.installed" : "native.helperNeeded",
                  color: serves ? "up" : "unknown")
                Text(
                  L10n.text(backend == "WireGuard" ? "native.wireguardEngine" : "native.openvpnEngine")
                ).font(.system(size: 11.48)).foregroundStyle(p.secondary)
                Spacer()
              } else {
                AppBadge(text: "Not available")
                Text(L10n.text("Native VPN provider pending")).font(.system(size: 11.48))
                  .foregroundStyle(p.secondary)
                Spacer()
              }
            }
          }
          Text(
            L10n.text(
              model.canStartConnections
                ? "native.backendsNote"
                : "Configuration import and analysis work. VPN activation and backend installation are not implemented in this native version."
            )
          ).font(.system(size: 10.92)).foregroundStyle(p.muted)
        }.padding(10.5)
      }
      settingsGroup("native.helper") { helperRow }
      settingsGroup("settings.groupStartup") {
        HStack {
          settingText("settings.startAtLogin", "native.startAtLoginSub")
          Spacer()
          Toggle(
            "",
            isOn: Binding(
              get: { loginItemEnabled },
              set: { enable in
                do {
                  if enable {
                    try SMAppService.mainApp.register()
                  } else {
                    try SMAppService.mainApp.unregister()
                  }
                } catch { model.error = "native.loginItemFailed" }
                loginItemEnabled = SMAppService.mainApp.status == .enabled
              })
          ).toggleStyle(.switch).controlSize(.small).labelsHidden()
        }.padding(.horizontal, 14).padding(.vertical, 10.5)
        Rectangle().fill(p.border).frame(height: 1)
        HStack {
          settingText("native.menuBar.setting", "native.menuBar.settingSub")
          Spacer()
          Toggle("", isOn: $showMenuBar).toggleStyle(.switch).controlSize(.small).labelsHidden()
        }.padding(.horizontal, 14).padding(.vertical, 10.5)
      }
      .onAppear { loginItemEnabled = SMAppService.mainApp.status == .enabled }
      settingsGroup("native.diagnostics") {
        HStack {
          settingText("native.importLog", "native.importLogHint")
          Spacer()
          Button(L10n.text("native.open")) { showingImportLog = true }
        }.padding(.horizontal, 14).padding(.vertical, 10.5)
      }
      .sheet(isPresented: $showingImportLog) {
        LogSheet(
          title: L10n.text("native.importLog"), load: { await model.importLog() },
          onClose: { showingImportLog = false }
        ).environment(\.palette, p).buttonStyle(TauriButtonStyle())
      }
      settingsGroup("Updates") {
        HStack {
          settingText("App updates", "Check for and install new versions")
          Spacer()
          Button(L10n.text("Check for updates")) {}.disabled(true).help(
            L10n.text("App updates are not implemented for local native builds."))
        }.padding(.horizontal, 14).padding(.vertical, 10.5)
      }
      settingsGroup("About") {
        HStack {
          settingText(
            "Network Orchestrator",
            L10n.text(
              "Version {value0}", ["value0": String(describing: model.capabilities?.version ?? "…")]
            ))
          Spacer()
          Text(L10n.text("macOS 27 · Native")).font(.system(size: 10.92)).foregroundStyle(p.muted)
        }.padding(.horizontal, 14).padding(.vertical, 10.5)
      }
    }
  }
  /// Install state of the privileged helper and its install/remove controls.
  private var helperState: (title: String, color: String) {
    let status = model.helperStatus
    switch model.helperRegistration {
    case .notFound: return ("native.helperState.missing", "unknown")
    case .requiresApproval: return ("native.helperState.approval", "warn")
    case .notRegistered:
      return status?.reachable == true
        ? ("native.helperState.ready", "up") : ("native.helperState.absent", "unknown")
    case .enabled:
      if status?.reachable == true { return ("native.helperState.ready", "up") }
      if status?.denied == true { return ("native.helperState.denied", "down") }
      return ("native.helperState.stopped", "warn")
    }
  }
  private var helperRow: some View {
    let state = helperState
    return VStack(alignment: .leading, spacing: 8) {
      HStack(spacing: 10.5) {
        AppBadge(text: state.title, color: state.color)
        if let version = model.helperStatus?.version, !version.isEmpty {
          Text("v" + version).font(.system(size: 11.48)).foregroundStyle(p.secondary)
        }
        Spacer()
        switch model.helperRegistration {
        case .notFound: EmptyView()
        case .requiresApproval:
          Button(L10n.text("native.helperApprove")) { HelperManager.openSystemSettings() }
        case .notRegistered:
          Button(L10n.text("native.helperInstall")) { Task { await model.installHelper() } }
        case .enabled:
          Button(L10n.text("native.helperRemove")) { Task { await model.removeHelper() } }
        }
      }
      Text(L10n.text("native.helperHint")).font(.system(size: 10.92)).foregroundStyle(p.muted)
        .fixedSize(horizontal: false, vertical: true)
    }.padding(10.5)
      .onAppear { Task { await model.refreshHelper() } }
  }
  private func settingText(_ label: String, _ detail: String) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      Text(L10n.text(label)).font(.system(size: 12.6, weight: .medium))
      Text(L10n.text(detail)).font(.system(size: 10.92)).foregroundStyle(p.muted)
    }
  }
  private func settingsGroup<C: View>(_ title: String, @ViewBuilder content: () -> C) -> some View {
    VStack(alignment: .leading, spacing: 7) {
      Text(L10n.text(title).uppercased()).font(.system(size: 10.5, weight: .semibold)).tracking(0.7)
        .foregroundStyle(p.muted).padding(.leading, 3.5)
      VStack(spacing: 0) { content() }.frame(maxWidth: .infinity, alignment: .leading).background(
        p.card, in: RoundedRectangle(cornerRadius: 12)
      ).overlay(RoundedRectangle(cornerRadius: 12).stroke(p.border, lineWidth: 1))
    }
  }
}

/// Dense single-line interface row matching the Tauri Network tab.
struct InterfaceRow: View {
  @Environment(\.palette) private var p
  @State private var hovered = false
  let interface: NetworkInterface
  private var meta: String {
    var parts = [interface.kind.label]
    if let tunnel = interface.tunnelType { parts.insert(tunnel, at: 0) }
    if let mtu = interface.mtu { parts.append("MTU \(mtu)") }
    if let speed = interface.linkSpeedMbps { parts.append("\(speed) Mbps") }
    return parts.joined(separator: " · ")
  }
  var body: some View {
    let up = interface.state == "up"
    HStack(spacing: 8) {
      Circle().fill(up ? p["up"] : p["unknown"]).frame(width: 7, height: 7)
      NativeIcon(name: NativeIcon.category(interface.category), size: 14).foregroundStyle(
        p.secondary)
      Text(interface.friendlyName).font(.system(size: 12.3, weight: .semibold)).lineLimit(1)
      Text(meta).font(.system(size: 10.92)).foregroundStyle(p.muted).lineLimit(1)
      Spacer(minLength: 12)
      Text(
        interface.addresses.first.map { "\($0.address)/\($0.prefixLen)" } ?? "—"
      ).font(.system(size: 11.2, weight: .medium, design: .monospaced)).lineLimit(1)
        .frame(width: 210, alignment: .leading)
      Group {
        if let rx = interface.rxBytes, let tx = interface.txBytes {
        HStack(spacing: 2) {
          NativeIcon(name: "ArrowDownIcon", size: 11)
          Text(Self.bytes(rx))
          NativeIcon(name: "ArrowUpIcon", size: 11).padding(.leading, 4)
          Text(Self.bytes(tx))
        }.font(.system(size: 10.92)).foregroundStyle(p.secondary)
        }
      }.frame(width: 160, alignment: .trailing)
      AppBadge(text: up ? "Up" : "Down", color: up ? "up" : "down")
    }
    .padding(.horizontal, 8).padding(.vertical, 6)
    .background(hovered ? p.hover : .clear)
    .overlay(alignment: .bottom) { Rectangle().fill(p.border).frame(height: 1) }
    .contentShape(Rectangle()).onHover { hovered = $0 }
  }
  static func bytes(_ value: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(clamping: value), countStyle: .binary)
  }
}
