import 'package:biometric_signature/biometric_signature.dart';
import 'package:biometric_signature/biometric_signature_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockBiometricSignaturePlatform
    with MockPlatformInterfaceMixin
    implements BiometricSignaturePlatform {
  BiometricAvailability _authAvailableResult = BiometricAvailability(
    canAuthenticate: true,
    hasEnrolledBiometrics: true,
    availableBiometrics: [BiometricType.fingerprint],
    reason: null,
  );
  bool _shouldThrowError = false;
  SignatureType _signatureType = SignatureType.rsa;

  void setAuthAvailableResult(BiometricAvailability result) {
    _authAvailableResult = result;
  }

  void setShouldThrowError(bool value) {
    _shouldThrowError = value;
  }

  void setSignatureType(SignatureType type) {
    _signatureType = type;
  }

  @override
  Future<BiometricAvailability> biometricAuthAvailable() async {
    if (_shouldThrowError) throw Exception('Auth check failed');
    return _authAvailableResult;
  }

  @override
  Future<KeyInfo> getKeyInfo(bool checkValidity, KeyFormat keyFormat) async {
    return KeyInfo(
      exists: true,
      isValid: true,
      algorithm: 'RSA',
      keySize: 2048,
      isHybridMode: false,
      publicKey: 'test_public_key',
    );
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
  ) async {
    if (_shouldThrowError) throw Exception('Key creation failed');

    final isEc = (signatureType ?? _signatureType) == SignatureType.ecdsa;
    return KeyCreationResult(
      publicKey: 'test_public_key',
      code: BiometricError.success,
      algorithm: isEc ? 'EC' : 'RSA',
      keySize: isEc ? 256 : 2048,
    );
  }

  @override
  Future<SignatureResult> createSignature(
    String payload,
    AndroidCreateSignatureConfig? androidConfig,
    IosCreateSignatureConfig? iosConfig,
    MacosCreateSignatureConfig? macosConfig,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  ) async {
    if (_shouldThrowError) throw Exception('Signing failed');

    return SignatureResult(
      signature: 'test_signature',
      publicKey: 'test_public_key',
      code: BiometricError.success,
      algorithm: 'RSA',
      keySize: 2048,
    );
  }

  @override
  Future<bool> deleteKeys() => Future.value(true);

  @override
  Future<DecryptResult> decrypt(
    String payload,
    PayloadFormat payloadFormat,
    AndroidDecryptConfig? androidConfig,
    IosDecryptConfig? iosConfig,
    MacosDecryptConfig? macosConfig,
    String? promptMessage,
  ) async {
    if (_shouldThrowError) throw Exception('Decryption failed');
    return DecryptResult(
      decryptedData: 'decrypted_$payload',
      code: BiometricError.success,
    );
  }
}

void main() {
  final BiometricSignaturePlatform initialPlatform =
      BiometricSignaturePlatform.instance;

  test('\$BiometricSignaturePlatform is the default instance', () {
    expect(initialPlatform, isInstanceOf<BiometricSignaturePlatform>());
  });

  group('biometricAuthAvailable', () {
    test('returns availability info', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.biometricAuthAvailable();
      expect(result.canAuthenticate, true);
      expect(result.hasEnrolledBiometrics, true);
      expect(result.availableBiometrics, contains(BiometricType.fingerprint));
    });

    test('handles unavailable biometrics', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.setAuthAvailableResult(
        BiometricAvailability(
          canAuthenticate: false,
          hasEnrolledBiometrics: false,
          availableBiometrics: [BiometricType.unavailable],
          reason: 'No biometric hardware',
        ),
      );
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.biometricAuthAvailable();
      expect(result.canAuthenticate, false);
      expect(result.reason, 'No biometric hardware');
    });
  });

  group('createKeys', () {
    test('RSA keys (default)', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createKeys();
      expect(result.publicKey, 'test_public_key');
      expect(result.algorithm, 'RSA');
      expect(result.keySize, 2048);
      expect(result.code, BiometricError.success);
    });

    test('EC keys', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createKeys(
        signatureType: SignatureType.ecdsa,
      );
      expect(result.algorithm, 'EC');
      expect(result.keySize, 256);
    });

    test('with Android config', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createKeys(
        androidConfig: AndroidCreateKeysConfig(
          enableDecryption: true,
          promptSubtitle: 'Test subtitle',
        ),
      );
      expect(result.code, BiometricError.success);
    });

    test('Error handling', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.setShouldThrowError(true);
      BiometricSignaturePlatform.instance = fakePlatform;

      expect(() => biometricSignature.createKeys(), throwsException);
    });
  });

  group('createSignature', () {
    test('Success with default options', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createSignature(
        payload: 'test_data',
      );
      expect(result.signature, 'test_signature');
      expect(result.publicKey, 'test_public_key');
      expect(result.code, BiometricError.success);
    });

    test('with custom prompt message', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.createSignature(
        payload: 'test_data',
        promptMessage: 'Please authenticate',
      );
      expect(result.code, BiometricError.success);
    });

    test('Error handling', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.setShouldThrowError(true);
      BiometricSignaturePlatform.instance = fakePlatform;

      expect(
        () => biometricSignature.createSignature(payload: 'test'),
        throwsException,
      );
    });
  });

  test('deleteKeys', () async {
    BiometricSignature biometricSignature = BiometricSignature();
    MockBiometricSignaturePlatform fakePlatform =
        MockBiometricSignaturePlatform();
    BiometricSignaturePlatform.instance = fakePlatform;

    expect(await biometricSignature.deleteKeys(), true);
  });

  test('biometricKeyExists', () async {
    BiometricSignature biometricSignature = BiometricSignature();
    MockBiometricSignaturePlatform fakePlatform =
        MockBiometricSignaturePlatform();
    BiometricSignaturePlatform.instance = fakePlatform;

    expect(await biometricSignature.biometricKeyExists(), true);
  });

  group('decrypt', () {
    test('Success', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      BiometricSignaturePlatform.instance = fakePlatform;

      final result = await biometricSignature.decrypt(
        payload: 'encrypted_payload',
        payloadFormat: PayloadFormat.base64,
      );
      expect(result.decryptedData, 'decrypted_encrypted_payload');
      expect(result.code, BiometricError.success);
    });

    test('Error handling', () async {
      BiometricSignature biometricSignature = BiometricSignature();
      MockBiometricSignaturePlatform fakePlatform =
          MockBiometricSignaturePlatform();
      fakePlatform.setShouldThrowError(true);
      BiometricSignaturePlatform.instance = fakePlatform;

      expect(
        () => biometricSignature.decrypt(
          payload: 'encrypted_payload',
          payloadFormat: PayloadFormat.base64,
        ),
        throwsException,
      );
    });
  });
}
