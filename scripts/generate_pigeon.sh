#!/bin/bash

# Script to generate Pigeon code and copy Swift file to macOS
# Usage: ./scripts/generate_pigeon.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🐦 Running Pigeon code generator..."
fvm use 3.35.7 && fvm flutter pub run pigeon --input pigeons/messages.dart

echo "📋 Copying generated Swift file to macOS..."
cp "$PROJECT_ROOT/ios/Classes/BiometricSignatureApi.swift" "$PROJECT_ROOT/macos/Classes/BiometricSignatureApi.swift"

echo "✅ Done! Generated code for:"
echo "   - Dart: lib/biometric_signature_platform_interface.pigeon.dart"
echo "   - Android: android/src/main/kotlin/.../BiometricSignatureApi.kt"
echo "   - iOS: ios/Classes/BiometricSignatureApi.swift"
echo "   - macOS: macos/Classes/BiometricSignatureApi.swift (copied from iOS)"
