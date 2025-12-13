import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(PigeonOptions(
  dartOut: 'lib/biometric_signature_platform_interface.pigeon.dart',
  dartOptions: DartOptions(),
  kotlinOut: 'android/src/main/kotlin/com/visionflutter/biometric_signature/BiometricSignatureApi.kt',
  kotlinOptions: KotlinOptions(package: 'com.visionflutter.biometric_signature'),
  swiftOut: 'ios/Classes/BiometricSignatureApi.swift',
  swiftOptions: SwiftOptions(),
  macosOut: 'macos/Classes/BiometricSignatureApi.swift',
  macosOptions: MacosOptions(),
))

enum BiometricType {
  face,
  fingerprint,
  iris,
  weak,
  strong,
  unavailable,
}

/// Standardized error codes for the plugin.
enum BiometricError {
  /// The operation was successful.
  success,
  /// The user canceled the operation.
  userCanceled,
  /// The system canceled the operation (e.g. another app took focus).
  systemCanceled,
  /// Biometric authentication is not available on this device.
  notAvailable,
  /// No biometrics are enrolled.
  notEnrolled,
  /// The user has not set a passcode/PIN.
  passcodeNotSet,
  /// The user is temporarily locked out due to too many failed attempts.
  lockedOut,
  /// The user is permanently locked out until they log in with a strong method.
  lockedOutPermanent,
  /// The requested key was not found.
  keyNotFound,
  /// The key has been invalidated (e.g. by new biometric enrollment).
  keyInvalidated,
  /// An unknown error occurred.
  unknown,
  /// The input payload was invalid (e.g. not valid Base64).
  invalidInput,
}

class BiometricAvailability {
  bool canAuthenticate;
  bool hasEnrolledBiometrics;
  List<BiometricType?> availableBiometrics;
  String? reason;
}

class KeyCreationResult {
  String? publicKey;
  Uint8List? publicKeyBytes;
  String? error;
  BiometricError? code;
  // Added for v8.5.0 parity (Refactored to Decrypting fields)
  String? algorithm;
  int? keySize;
  String? decryptingPublicKey;
  String? decryptingAlgorithm;
  int? decryptingKeySize;
  bool? isHybridMode;
}

class SignatureResult {
  String? signature;
  Uint8List? signatureBytes;
  String? publicKey;
  String? error;
  BiometricError? code;
  // Added for v8.5.0 parity
  String? algorithm;
  int? keySize;
}

class DecryptResult {
  String? decryptedData;
  String? error;
  BiometricError? code;
}


enum SignatureType {
  rsa,
  ecdsa,
}

/// Configuration for Android key creation.
class AndroidCreateKeysConfig {
  bool? enableDecryption;
  String? promptSubtitle;
  String? promptDescription;
  String? cancelButtonText;
}

/// Configuration for iOS key creation.
class IosCreateKeysConfig {
  String? reserved;
}

/// Configuration for macOS key creation.
class MacosCreateKeysConfig {
  String? reserved;
}

/// Configuration for Android signature creation.
class AndroidCreateSignatureConfig {
  String? promptSubtitle;
  String? promptDescription;
  String? cancelButtonText;
  bool? allowDeviceCredentials;
}

/// Configuration for iOS signature creation.
class IosCreateSignatureConfig {
  bool? shouldMigrate;
}

/// Configuration for macOS signature creation.
class MacosCreateSignatureConfig {
  String? reserved;
}

/// Configuration for Android decryption.
class AndroidDecryptConfig {
  String? promptSubtitle;
  String? promptDescription;
  String? cancelButtonText;
  bool? allowDeviceCredentials;
}

/// Configuration for iOS decryption.
class IosDecryptConfig {
  bool? shouldMigrate;
}

/// Configuration for macOS decryption.
class MacosDecryptConfig {
  String? reserved;
}

enum KeyFormat {
  base64,
  pem,
  hex,
  raw,
}

enum SignatureFormat {
  base64,
  hex,
  raw,
}

enum PayloadFormat {
  base64,
  hex,
  raw,
}

@HostApi()
abstract class BiometricSignatureApi {
  /// Checks if biometric authentication is available.
  BiometricAvailability getBiometricAvailability();

  /// Creates a new key pair.
  @async
  KeyCreationResult createKeys(
      AndroidCreateKeysConfig? androidConfig,
      IosCreateKeysConfig? iosConfig,
      MacosCreateKeysConfig? macosConfig,
      bool? useDeviceCredentials,
      SignatureType? signatureType,
      bool? setInvalidatedByBiometricEnrollment,
      KeyFormat keyFormat,
      bool enforceBiometric,
      String? promptMessage);

  /// Creates a signature.
  @async
  SignatureResult createSignature(
      String? payload,
      AndroidCreateSignatureConfig? androidConfig,
      IosCreateSignatureConfig? iosConfig,
      MacosCreateSignatureConfig? macosConfig,
      SignatureFormat signatureFormat,
      KeyFormat keyFormat,
      String? promptMessage);

  /// Decrypts data.
  @async
  DecryptResult decrypt(
      String? payload,
      PayloadFormat payloadFormat,
      AndroidDecryptConfig? androidConfig,
      IosDecryptConfig? iosConfig,
      MacosDecryptConfig? macosConfig,
      String? promptMessage);

  /// Deletes keys.
  bool deleteKeys();

  /// Checks if a key exists.
  @async
  bool biometricKeyExists(bool checkValidity);
}
