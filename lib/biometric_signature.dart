import 'biometric_signature_platform_interface.dart';

export 'biometric_signature_platform_interface.dart'
    show
        CreateKeysConfig,
        CreateSignatureConfig,
        DecryptConfig,
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
  ///
  /// [config] contains platform-specific options. See [CreateKeysConfig] for
  /// available options and which platforms they apply to.
  /// [keyFormat] specifies the output format for the public key.
  /// [promptMessage] is the message shown during biometric authentication.
  ///
  /// Returns a [KeyCreationResult] containing the public key or error details.
  Future<KeyCreationResult> createKeys({
    CreateKeysConfig? config,
    KeyFormat keyFormat = KeyFormat.base64,
    String? promptMessage,
  }) async {
    return BiometricSignaturePlatform.instance.createKeys(
      config,
      keyFormat,
      promptMessage,
    );
  }

  /// Creates a digital signature using biometric authentication.
  ///
  /// [payload] is the data to sign.
  /// [config] contains platform-specific options. See [CreateSignatureConfig].
  /// [signatureFormat] specifies the output format for the signature.
  /// [keyFormat] specifies the output format for the public key.
  /// [promptMessage] is the message shown during biometric authentication.
  ///
  /// Returns a [SignatureResult] containing the signature or error details.
  Future<SignatureResult> createSignature({
    required String payload,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat = SignatureFormat.base64,
    KeyFormat keyFormat = KeyFormat.base64,
    String? promptMessage,
  }) async {
    return BiometricSignaturePlatform.instance.createSignature(
      payload,
      config,
      signatureFormat,
      keyFormat,
      promptMessage,
    );
  }

  /// Decrypts data using biometric authentication.
  ///
  /// Note: Not supported on Windows.
  ///
  /// [payload] is the encrypted data.
  /// [payloadFormat] specifies the format of the encrypted data.
  /// [config] contains platform-specific options. See [DecryptConfig].
  /// [promptMessage] is the message shown during biometric authentication.
  ///
  /// Returns a [DecryptResult] containing the decrypted data or error details.
  Future<DecryptResult> decrypt({
    required String payload,
    required PayloadFormat payloadFormat,
    DecryptConfig? config,
    String? promptMessage,
  }) async {
    return BiometricSignaturePlatform.instance.decrypt(
      payload,
      payloadFormat,
      config,
      promptMessage,
    );
  }

  /// Deletes all active biometric key material.
  ///
  /// Returns `true` if keys were deleted or no keys existed.
  Future<bool> deleteKeys() async {
    return BiometricSignaturePlatform.instance.deleteKeys();
  }

  /// Determines whether biometric authentication is available on the device.
  ///
  /// Returns a [BiometricAvailability] with details about available biometrics.
  Future<BiometricAvailability> biometricAuthAvailable() async {
    return BiometricSignaturePlatform.instance.biometricAuthAvailable();
  }

  /// Gets detailed information about existing biometric keys.
  ///
  /// [checkValidity] whether to verify key hasn't been invalidated.
  /// [keyFormat] output format for the public key.
  ///
  /// Returns a [KeyInfo] with key metadata.
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
