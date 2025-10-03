// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "KhipuTweetNacl",
    platforms: [
        .iOS(.v12)
    ],
    products: [
        .library(
            name: "KhipuTweetNacl",
            targets: ["KhipuTweetNacl"]
        ),
    ],
    dependencies: [],
    targets: [
        // Target C: expone ctweetnacl.h a SwiftPM
        .target(
            name: "CTweetNacl",
            publicHeadersPath: "." // usa el header donde está (p.ej. Sources/CTweetNacl/ctweetnacl.h)
        ),
        // Wrapper Swift (depende del C)
        .target(
            name: "KhipuTweetNacl",
            dependencies: ["CTweetNacl"]
        ),
        // Tests (ajusta nombres/paths si difieren)
        .testTarget(
            name: "KhipuTweetNaclTests",
            dependencies: ["KhipuTweetNacl"],
            resources: [
                .process("SecretboxTestData.json"),
                .process("BoxTestData.json"),
                .process("ScalarMultiTestData.json"),
                .process("SignTestData.json")
            ]
        ),
    ]
)

