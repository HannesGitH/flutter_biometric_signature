import 'biometric_signature_platform_interface.dart';

export 'biometric_signature_windows.dart';
export 'biometric_signature_platform_interface.dart'
    show
        AndroidCreateKeysConfig,
        IosCreateKeysConfig,
        MacosCreateKeysConfig,
        AndroidCreateSignatureConfig,
        IosCreateSignatureConfig,
        MacosCreateSignatureConfig,
        AndroidDecryptConfig,
        IosDecryptConfig,
        MacosDecryptConfig,
        SignatureType,
        KeyFormat,
        SignatureFormat,
        PayloadFormat,
        BiometricError,
        BiometricType,
        BiometricAvailability,
        KeyCreationResult,
        SignatureResult,
        DecryptResult,
        KeyInfo;

/// High-level API for interacting with the Biometric Signature plugin.
class BiometricSignature {
  /// Creates a new biometric-protected key pair.
  Future<KeyCreationResult> createKeys({
    AndroidCreateKeysConfig? androidConfig,
    IosCreateKeysConfig? iosConfig,
    MacosCreateKeysConfig? macosConfig,
    bool useDeviceCredentials = false,
    SignatureType signatureType = SignatureType.rsa,
    bool setInvalidatedByBiometricEnrollment = false,
    KeyFormat keyFormat = KeyFormat.base64,
    bool enforceBiometric = false,
    String? promptMessage,
  }) async {
    return BiometricSignaturePlatform.instance.createKeys(
      androidConfig,
      iosConfig,
      macosConfig,
      useDeviceCredentials,
      signatureType,
      setInvalidatedByBiometricEnrollment,
      keyFormat,
      enforceBiometric,
      promptMessage,
    );
  }

  /// Creates a digital signature using biometric authentication.
  Future<SignatureResult> createSignature({
    required String payload,
    AndroidCreateSignatureConfig? androidConfig,
    IosCreateSignatureConfig? iosConfig,
    MacosCreateSignatureConfig? macosConfig,
    SignatureFormat signatureFormat = SignatureFormat.base64,
    KeyFormat keyFormat = KeyFormat.base64,
    String? promptMessage,
  }) async {
    return BiometricSignaturePlatform.instance.createSignature(
      payload,
      androidConfig,
      iosConfig,
      macosConfig,
      signatureFormat,
      keyFormat,
      promptMessage,
    );
  }

  /// Decrypts data.
  Future<DecryptResult> decrypt({
    required String payload,
    required PayloadFormat payloadFormat,
    AndroidDecryptConfig? androidConfig,
    IosDecryptConfig? iosConfig,
    MacosDecryptConfig? macosConfig,
    String? promptMessage,
  }) async {
    return BiometricSignaturePlatform.instance.decrypt(
      payload,
      payloadFormat,
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
    return BiometricSignaturePlatform.instance.biometricAuthAvailable();
  }

  /// Gets detailed information about existing biometric keys.
  Future<KeyInfo> getKeyInfo({
    bool checkValidity = false,
    KeyFormat keyFormat = KeyFormat.base64,
  }) async {
    return BiometricSignaturePlatform.instance.getKeyInfo(
      checkValidity,
      keyFormat,
    );
  }

  /// Checks whether a hardware-backed signing key currently exists.
  ///
  /// This is a convenience wrapper around [getKeyInfo].
  Future<bool> biometricKeyExists({bool checkValidity = false}) async {
    final info = await getKeyInfo(checkValidity: checkValidity);
    return (info.exists ?? false) && (info.isValid ?? true);
  }
}
