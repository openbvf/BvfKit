// swift-tools-version: 6.1
import PackageDescription

let package = Package(
  name: "BvfKit",
  platforms: [
    .macOS(.v15),
    .iOS(.v17),
    .watchOS(.v10)
  ],
  products: [
    .library(
      name: "BvfKit",
      targets: ["BvfKit"]
    )
  ],
  dependencies: [
    .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.10.0")
  ],
  targets: [
    .target(
      name: "BvfKit",
      dependencies: [
        .product(name: "Clibsodium", package: "swift-sodium")
      ]
    ),
    .testTarget(
      name: "BvfKitTests",
      dependencies: ["BvfKit"]
    )
  ]
)
