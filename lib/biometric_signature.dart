import 'biometric_signature_platform_interface.dart';

export 'biometric_signature_platform_interface.dart'
    show
        AndroidConfig,
        IosConfig,
        MacosConfig,
        SignatureType,
        KeyFormat,
        BiometricError,
        BiometricType,
        BiometricAvailability,
        KeyCreationResult,
        SignatureResult,
        DecryptResult;

/// High-level API for interacting with the Biometric Signature plugin.
class BiometricSignature {
  /// Creates a new biometric-protected key pair.
  Future<KeyCreationResult> createKeys({
    AndroidConfig? androidConfig,
    IosConfig? iosConfig,
    MacosConfig? macosConfig,
    KeyFormat keyFormat = KeyFormat.base64,
    bool enforceBiometric = false,
    String? promptMessage,
  }) async {
    return BiometricSignaturePlatform.instance.createKeys(
      androidConfig,
      iosConfig,
      macosConfig,
      keyFormat,
      enforceBiometric,
      promptMessage,
    );
  }

  /// Creates a digital signature using biometric authentication.
  Future<SignatureResult> createSignature({
    required String payload,
    AndroidConfig? androidConfig,
    IosConfig? iosConfig,
    MacosConfig? macosConfig,
    KeyFormat keyFormat = KeyFormat.base64,
    String? promptMessage,
  }) async {
    return BiometricSignaturePlatform.instance.createSignature(
      payload,
      androidConfig,
      iosConfig,
      macosConfig,
      keyFormat,
      promptMessage,
    );
  }

  /// Decrypts a payload using biometric authentication.
  Future<DecryptResult> decrypt({
    required String payload,
    AndroidConfig? androidConfig,
    IosConfig? iosConfig,
    MacosConfig? macosConfig,
    String? promptMessage,
  }) async {
    return BiometricSignaturePlatform.instance.decrypt(
      payload,
      androidConfig,
      iosConfig,
      macosConfig,
      promptMessage,
    );
  }

  /// Deletes all active biometric key material.
  Future<bool> deleteKeys() async {
    return BiometricSignaturePlatform.instance.deleteKeys();
  }

  /// Determines whether biometric authentication is available on the device.
  Future<BiometricAvailability> biometricAuthAvailable() async {
    return BiometricSignaturePlatform.instance.getBiometricAvailability();
  }

  /// Checks whether a hardware-backed signing key currently exists.
  Future<bool> biometricKeyExists({bool checkValidity = false}) async {
    return BiometricSignaturePlatform.instance
        .biometricKeyExists(checkValidity);
  }
}
