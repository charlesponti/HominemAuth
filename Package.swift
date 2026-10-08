// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "HominemAuth",
    platforms: [
        // The core (HominemAuth) runs on iOS 15 / macOS 12. HominemAuthUI uses @Observable, so its
        // types are marked @available(iOS 17, macOS 14) and only they need the newer systems.
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "HominemAuth", targets: ["HominemAuth"]),
        .library(name: "HominemAuthUI", targets: ["HominemAuthUI"])
    ],
    targets: [
        .target(
            name: "HominemAuth",
            path: "Sources/HominemAuth"
        ),
        .target(
            name: "HominemAuthUI",
            dependencies: ["HominemAuth"],
            path: "Sources/HominemAuthUI"
        ),
        .testTarget(
            name: "HominemAuthTests",
            dependencies: ["HominemAuth"],
            path: "Tests/HominemAuthTests"
        )
    ]
)
