// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "NetworkOrchestratorMac",
  platforms: [.macOS("27.0")],
  products: [.executable(name: "NetworkOrchestrator", targets: ["NetworkOrchestrator"])],
  targets: [
    .systemLibrary(name: "NativeCore", path: "Sources/NativeCore"),
    .executableTarget(
      name: "NetworkOrchestrator", dependencies: ["NativeCore"],
      resources: [.process("Resources")],
      linkerSettings: [
        .unsafeFlags(["-L", "../target/macos-bridge"]),
        .linkedLibrary("net_manager_macos_bridge"),
        .linkedFramework("Security"), .linkedFramework("SystemConfiguration"),
        .linkedFramework("CoreFoundation"),
        .linkedLibrary("resolv"),
        .linkedLibrary("proc"),
      ]
    ),
    .testTarget(name: "NativeTests", dependencies: ["NetworkOrchestrator"]),
  ]
)
