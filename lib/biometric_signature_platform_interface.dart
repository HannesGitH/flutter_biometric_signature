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
  Future<BiometricAvailability> getBiometricAvailability() {
    throw UnimplementedError(
      'getBiometricAvailability() has not been implemented.',
    );
  }

  /// Creates a new key pair.
  Future<KeyCreationResult> createKeys(
    AndroidCreateKeysConfig? androidConfig,
    IosCreateKeysConfig? iosConfig,
    MacosCreateKeysConfig? macosConfig,
    bool? useDeviceCredentials,
    SignatureType? signatureType,
    bool? setInvalidatedByBiometricEnrollment,
    KeyFormat keyFormat,
    bool enforceBiometric,
    String? promptMessage,
  ) {
    throw UnimplementedError('createKeys() has not been implemented.');
  }

  /// Creates a signature.
  Future<SignatureResult> createSignature(
    String? payload,
    AndroidCreateSignatureConfig? androidConfig,
    IosCreateSignatureConfig? iosConfig,
    MacosCreateSignatureConfig? macosConfig,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  ) {
    throw UnimplementedError('createSignature() has not been implemented.');
  }

  /// Decrypts data.
  Future<DecryptResult> decrypt(
    String? payload,
    PayloadFormat payloadFormat,
    AndroidDecryptConfig? androidConfig,
    IosDecryptConfig? iosConfig,
    MacosDecryptConfig? macosConfig,
    String? promptMessage,
  ) {
    throw UnimplementedError('decrypt() has not been implemented.');
  }

  /// Deletes keys.
  Future<bool> deleteKeys() {
    throw UnimplementedError('deleteKeys() has not been implemented.');
  }

  /// Checks if a key exists.
  Future<bool> biometricKeyExists(bool checkValidity) {
    throw UnimplementedError('biometricKeyExists() has not been implemented.');
  }
}

class _PigeonBiometricSignature extends BiometricSignaturePlatform {
  final BiometricSignatureApi _api = BiometricSignatureApi();

  @override
  Future<BiometricAvailability> getBiometricAvailability() {
    return _api.getBiometricAvailability();
  }

  @override
  Future<KeyCreationResult> createKeys(
    AndroidCreateKeysConfig? androidConfig,
    IosCreateKeysConfig? iosConfig,
    MacosCreateKeysConfig? macosConfig,
    bool? useDeviceCredentials,
    SignatureType? signatureType,
    bool? setInvalidatedByBiometricEnrollment,
    KeyFormat keyFormat,
    bool enforceBiometric,
    String? promptMessage,
  ) {
    return _api.createKeys(
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

  @override
  Future<SignatureResult> createSignature(
    String? payload,
    AndroidCreateSignatureConfig? androidConfig,
    IosCreateSignatureConfig? iosConfig,
    MacosCreateSignatureConfig? macosConfig,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  ) {
    return _api.createSignature(
      payload,
      androidConfig,
      iosConfig,
      macosConfig,
      signatureFormat,
      keyFormat,
      promptMessage,
    );
  }

  @override
  Future<DecryptResult> decrypt(
    String? payload,
    PayloadFormat payloadFormat,
    AndroidDecryptConfig? androidConfig,
    IosDecryptConfig? iosConfig,
    MacosDecryptConfig? macosConfig,
    String? promptMessage,
  ) {
    return _api.decrypt(
      payload,
      payloadFormat,
      androidConfig,
      iosConfig,
      macosConfig,
      promptMessage,
    );
  }

  @override
  Future<bool> deleteKeys() {
    return _api.deleteKeys();
  }

  @override
  Future<bool> biometricKeyExists(bool checkValidity) {
    return _api.biometricKeyExists(checkValidity);
  }
}
