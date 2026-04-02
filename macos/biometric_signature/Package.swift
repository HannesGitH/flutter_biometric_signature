// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "biometric_signature",
    platforms: [
        .macOS("10.15")
    ],
    products: [
        .library(name: "biometric-signature", targets: ["biometric_signature"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "biometric_signature",
            dependencies: [],
            resources: [
                .process("PrivacyInfo.xcprivacy"),
            ]
        )
    ]
)
