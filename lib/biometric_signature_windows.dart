// Windows-specific implementation of biometric_signature plugin
// Uses MethodChannel with StandardMessageCodec to communicate with native code
// instead of Pigeon's custom codec

import 'package:flutter/services.dart';
import 'biometric_signature_platform_interface.dart';

/// Windows implementation of [BiometricSignaturePlatform].
///
/// This implementation uses MethodChannel instead of Pigeon's BasicMessageChannel
/// because Pigeon's custom codec (with custom type IDs) is not available in the
/// C++ Flutter plugin ecosystem without manual implementation.
class BiometricSignatureWindows extends BiometricSignaturePlatform {
  /// The method channel used to interact with the native Windows code.
  static const MethodChannel _channel = MethodChannel(
    'com.visionflutter.biometric_signature',
  );

  /// Registers this class as the default instance of [BiometricSignaturePlatform].
  static void registerWith() {
    BiometricSignaturePlatform.instance = BiometricSignatureWindows();
  }

  @override
  Future<BiometricAvailability> biometricAuthAvailable() async {
    final result = await _channel.invokeMethod<Map<Object?, Object?>>(
      'biometricAuthAvailable',
    );
    if (result == null) {
      return BiometricAvailability(
        canAuthenticate: false,
        hasEnrolledBiometrics: false,
        availableBiometrics: [],
        reason: 'No response from native code',
      );
    }

    return BiometricAvailability(
      canAuthenticate: result['canAuthenticate'] as bool? ?? false,
      hasEnrolledBiometrics: result['hasEnrolledBiometrics'] as bool? ?? false,
      availableBiometrics: _parseBiometricTypes(result['availableBiometrics']),
      reason: result['reason'] as String?,
    );
  }

  @override
  Future<KeyCreationResult> createKeys(
    CreateKeysConfig? config,
    KeyFormat keyFormat,
    String? promptMessage,
  ) async {
    final result = await _channel.invokeMethod<Map<Object?, Object?>>(
      'createKeys',
      {'promptMessage': promptMessage, 'keyFormat': keyFormat.index},
    );

    if (result == null) {
      return KeyCreationResult(error: 'No response from native code');
    }

    return KeyCreationResult(
      publicKey: result['publicKey'] as String?,
      publicKeyBytes: _parseBytes(result['publicKeyBytes']),
      error: result['error'] as String?,
      code: _parseBiometricError(result['code']),
      algorithm: result['algorithm'] as String?,
      keySize: result['keySize'] as int?,
      isHybridMode: result['isHybridMode'] as bool?,
    );
  }

  @override
  Future<SignatureResult> createSignature(
    String payload,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  ) async {
    final result = await _channel
        .invokeMethod<Map<Object?, Object?>>('createSignature', {
          'payload': payload,
          'signatureFormat': signatureFormat.index,
          'keyFormat': keyFormat.index,
          'promptMessage': promptMessage,
        });

    if (result == null) {
      return SignatureResult(error: 'No response from native code');
    }

    return SignatureResult(
      signature: result['signature'] as String?,
      signatureBytes: _parseBytes(result['signatureBytes']),
      publicKey: result['publicKey'] as String?,
      error: result['error'] as String?,
      code: _parseBiometricError(result['code']),
      algorithm: result['algorithm'] as String?,
      keySize: result['keySize'] as int?,
    );
  }

  @override
  Future<bool> deleteKeys() async {
    final result = await _channel.invokeMethod<bool>('deleteKeys');
    return result ?? true;
  }

  @override
  Future<KeyInfo> getKeyInfo(bool checkValidity, KeyFormat keyFormat) async {
    final result = await _channel.invokeMethod<Map<Object?, Object?>>(
      'getKeyInfo',
      {'checkValidity': checkValidity, 'keyFormat': keyFormat.index},
    );

    if (result == null) {
      return KeyInfo(exists: false);
    }

    return KeyInfo(
      exists: result['exists'] as bool? ?? false,
      isValid: result['isValid'] as bool?,
      algorithm: result['algorithm'] as String?,
      keySize: result['keySize'] as int?,
      isHybridMode: result['isHybridMode'] as bool?,
      publicKey: result['publicKey'] as String?,
    );
  }

  @override
  Future<DecryptResult> decrypt(
    String payload,
    PayloadFormat payloadFormat,
    DecryptConfig? config,
    String? promptMessage,
  ) async {
    // Windows Hello doesn't support decryption
    return DecryptResult(
      error: 'Decryption is not supported on Windows',
      code: BiometricError.notAvailable,
    );
  }

  List<BiometricType?> _parseBiometricTypes(Object? value) {
    if (value == null) return [];
    if (value is! List) return [];

    return value.map((e) {
      if (e is int && e >= 0 && e < BiometricType.values.length) {
        return BiometricType.values[e];
      }
      return null;
    }).toList();
  }

  BiometricError? _parseBiometricError(Object? value) {
    if (value == null) return null;
    if (value is int && value >= 0 && value < BiometricError.values.length) {
      return BiometricError.values[value];
    }
    return null;
  }

  Uint8List? _parseBytes(Object? value) {
    if (value == null) return null;
    if (value is Uint8List) return value;
    if (value is List<int>) return Uint8List.fromList(value);
    return null;
  }
}
