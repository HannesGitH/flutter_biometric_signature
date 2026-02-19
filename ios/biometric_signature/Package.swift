// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "biometric_signature",
    platforms: [
        .iOS("13.0")
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

                // If you have other resources that need to be bundled with your plugin, refer to
                // the following instructions to add them:
                // https://developer.apple.com/documentation/xcode/bundling-resources-with-a-swift-package
            ]
        )
    ]
)
