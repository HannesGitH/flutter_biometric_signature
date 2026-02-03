import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'biometric_signature_platform_interface.pigeon.dart';

export 'biometric_signature_platform_interface.pigeon.dart';

/// Platform interface that defines the methods exposed to plugin
/// implementations.
abstract class BiometricSignaturePlatform extends PlatformInterface {
  /// Constructs a BiometricSignaturePlatform.
  BiometricSignaturePlatform() : super(token: _token);

  static final Object _token = Object();

  static BiometricSignaturePlatform _instance = _PigeonBiometricSignature();

  /// The default instance of [BiometricSignaturePlatform] to use.
  static BiometricSignaturePlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [BiometricSignaturePlatform] when
  /// they register themselves.
  static set instance(BiometricSignaturePlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  /// Checks if biometric authentication is available.
  Future<BiometricAvailability> biometricAuthAvailable() {
    throw UnimplementedError(
      'biometricAuthAvailable() has not been implemented.',
    );
  }

  /// Creates a new key pair.
  Future<KeyCreationResult> createKeys(
    CreateKeysConfig? config,
    KeyFormat keyFormat,
    String? promptMessage,
  ) {
    throw UnimplementedError('createKeys() has not been implemented.');
  }

  /// Creates a signature.
  Future<SignatureResult> createSignature(
    String payload,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  ) {
    throw UnimplementedError('createSignature() has not been implemented.');
  }

  /// Decrypts data.
  Future<DecryptResult> decrypt(
    String payload,
    PayloadFormat payloadFormat,
    DecryptConfig? config,
    String? promptMessage,
  ) {
    throw UnimplementedError('decrypt() has not been implemented.');
  }

  /// Deletes keys.
  Future<bool> deleteKeys() {
    throw UnimplementedError('deleteKeys() has not been implemented.');
  }

  /// Gets detailed information about existing biometric keys.
  Future<KeyInfo> getKeyInfo(bool checkValidity, KeyFormat keyFormat) {
    throw UnimplementedError('getKeyInfo() has not been implemented.');
  }

  /// Performs simple biometric authentication without cryptographic operations.
  Future<SimplePromptResult> simplePrompt(
    String promptMessage,
    SimplePromptConfig? config,
  ) {
    throw UnimplementedError('simplePrompt() has not been implemented.');
  }
}

class _PigeonBiometricSignature extends BiometricSignaturePlatform {
  final BiometricSignatureApi _api = BiometricSignatureApi();

  @override
  Future<BiometricAvailability> biometricAuthAvailable() {
    return _api.biometricAuthAvailable();
  }

  @override
  Future<KeyCreationResult> createKeys(
    CreateKeysConfig? config,
    KeyFormat keyFormat,
    String? promptMessage,
  ) {
    return _api.createKeys(config, keyFormat, promptMessage);
  }

  @override
  Future<SignatureResult> createSignature(
    String payload,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  ) {
    return _api.createSignature(
      payload,
      config,
      signatureFormat,
      keyFormat,
      promptMessage,
    );
  }

  @override
  Future<DecryptResult> decrypt(
    String payload,
    PayloadFormat payloadFormat,
    DecryptConfig? config,
    String? promptMessage,
  ) {
    return _api.decrypt(payload, payloadFormat, config, promptMessage);
  }

  @override
  Future<bool> deleteKeys() {
    return _api.deleteKeys();
  }

  @override
  Future<KeyInfo> getKeyInfo(bool checkValidity, KeyFormat keyFormat) {
    return _api.getKeyInfo(checkValidity, keyFormat);
  }

  @override
  Future<SimplePromptResult> simplePrompt(
    String promptMessage,
    SimplePromptConfig? config,
  ) {
    return _api.simplePrompt(promptMessage, config);
  }
}
