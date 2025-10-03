# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

### Testing
```bash
# Run all tests using Swift Package Manager
swift test

# Run tests for a specific test case
swift test --filter NaclBox_Tests

# Build without testing
swift build

# Clean build artifacts
swift build --clean
```

### Xcode-based Testing
```bash
# Build and test for iOS (requires Xcode)
xcodebuild test -scheme TweetNacl-iOS -project TweetNacl.xcodeproj -destination 'platform=iOS Simulator,name=iPhone 15'

# Build only
xcodebuild build -scheme TweetNacl-iOS -project TweetNacl.xcodeproj
```

## Architecture

This is a Swift wrapper around TweetNaCl cryptographic library providing authenticated encryption and digital signatures. The codebase consists of:

**Core Structure:**
- `Sources/CTweetNacl/` - C implementation of TweetNaCl algorithms
- `Sources/TweetNacl/` - Swift wrapper providing high-level API
  - `TweetNacl.swift` - Main implementation with NaclBox, NaclSecretBox, NaclScalarMult, and NaclSign
  - `Constant.swift` - Cryptographic constants (key sizes, nonce lengths, etc.)

**Cryptographic Capabilities:**
- **NaclBox**: Public-key authenticated encryption (curve25519-xsalsa20-poly1305)
- **NaclSecretBox**: Secret-key authenticated encryption (xsalsa20-poly1305)
- **NaclScalarMult**: Scalar multiplication on curve25519
- **NaclSign**: Digital signatures using Ed25519

**Test Structure:**
- Tests use JSON test vectors located in `Tests/TweetNaclTests/`
- Test files correspond to each cryptographic primitive (Box, Secretbox, ScalarMulti, Sign)

## Key Implementation Details

- All cryptographic operations work with Foundation's `Data` type
- Error handling uses Swift's throw mechanism with `NaclUtil.NaclUtilError` enum
- Platform-specific secure random generation (SecRandomCopyBytes on Apple platforms, /dev/urandom on Linux)
- The library maintains constant-time operations for cryptographic security