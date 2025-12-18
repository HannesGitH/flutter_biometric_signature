import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(
  PigeonOptions(
    dartOut: 'lib/biometric_signature_platform_interface.pigeon.dart',
    dartOptions: DartOptions(),
    kotlinOut:
        'android/src/main/kotlin/com/visionflutter/biometric_signature/BiometricSignatureApi.kt',
    kotlinOptions: KotlinOptions(
      package: 'com.visionflutter.biometric_signature',
    ),
    swiftOut: 'ios/Classes/BiometricSignatureApi.swift',
    swiftOptions: SwiftOptions(),
  ),
)
/// Types of biometric authentication supported by the device.
enum BiometricType {
  /// Face recognition (Face ID on iOS, face unlock on Android).
  face,

  /// Fingerprint recognition (Touch ID on iOS/macOS, fingerprint on Android).
  fingerprint,

  /// Iris scanner (Android only, rare on consumer devices).
  iris,

  /// Multiple biometric types are available on the device.
  multiple,

  /// No biometric hardware available or biometrics are disabled.
  unavailable,
}

/// Standardized error codes for the plugin.
enum BiometricError {
  /// The operation was successful.
  success,

  /// The user canceled the operation.
  userCanceled,

  /// Biometric authentication is not available on this device.
  notAvailable,

  /// No biometrics are enrolled.
  notEnrolled,

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
  bool? canAuthenticate;
  bool? hasEnrolledBiometrics;
  List<BiometricType?>? availableBiometrics;
  String? reason;
}

class KeyCreationResult {
  String? publicKey;
  Uint8List? publicKeyBytes;
  String? error;
  BiometricError? code;
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
  String? algorithm;
  int? keySize;
}

class DecryptResult {
  String? decryptedData;
  String? error;
  BiometricError? code;
}

/// Detailed information about existing biometric keys.
class KeyInfo {
  /// Whether any biometric key exists on the device.
  bool? exists;

  /// Whether the key is still valid (not invalidated by biometric changes).
  /// Only populated when `checkValidity: true` is passed.
  bool? isValid;

  /// The algorithm of the signing key (e.g., "RSA", "EC").
  String? algorithm;

  /// The key size in bits (e.g., 2048 for RSA, 256 for EC).
  int? keySize;

  /// Whether the key is in hybrid mode (separate signing and decryption keys).
  bool? isHybridMode;

  /// Signing key public key (formatted according to the requested format).
  String? publicKey;

  /// Decryption key public key for hybrid mode.
  String? decryptingPublicKey;

  /// Algorithm of the decryption key (hybrid mode only).
  String? decryptingAlgorithm;

  /// Key size of the decryption key in bits (hybrid mode only).
  int? decryptingKeySize;
}

/// The cryptographic algorithm to use for key generation.
enum SignatureType {
  /// RSA-2048 (Android: native, iOS/macOS: hybrid mode with Secure Enclave EC).
  rsa,

  /// ECDSA P-256 (hardware-backed on all platforms).
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

/// Output format for public keys.
enum KeyFormat {
  /// Base64-encoded DER (SubjectPublicKeyInfo).
  base64,

  /// PEM format with BEGIN/END PUBLIC KEY headers.
  pem,

  /// Hexadecimal-encoded DER.
  hex,

  /// Raw DER bytes (returned via `publicKeyBytes`).
  raw,
}

/// Output format for cryptographic signatures.
enum SignatureFormat {
  /// Base64-encoded signature bytes.
  base64,

  /// Hexadecimal-encoded signature bytes.
  hex,

  /// Raw signature bytes (returned via `signatureBytes`).
  raw,
}

/// Input format for encrypted payloads to decrypt.
enum PayloadFormat {
  /// Base64-encoded ciphertext.
  base64,

  /// Hexadecimal-encoded ciphertext.
  hex,

  /// Raw UTF-8 string (not recommended for binary data).
  raw,
}

@HostApi()
abstract class BiometricSignatureApi {
  /// Checks if biometric authentication is available.
  BiometricAvailability biometricAuthAvailable();

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
    String? promptMessage,
  );

  /// Creates a signature.
  @async
  SignatureResult createSignature(
    String payload,
    AndroidCreateSignatureConfig? androidConfig,
    IosCreateSignatureConfig? iosConfig,
    MacosCreateSignatureConfig? macosConfig,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  );

  /// Decrypts data.
  @async
  DecryptResult decrypt(
    String payload,
    PayloadFormat payloadFormat,
    AndroidDecryptConfig? androidConfig,
    IosDecryptConfig? iosConfig,
    MacosDecryptConfig? macosConfig,
    String? promptMessage,
  );

  /// Deletes keys.
  bool deleteKeys();

  /// Gets detailed information about existing biometric keys.
  ///
  /// Returns key metadata including algorithm, size, validity, and public keys.
  @async
  KeyInfo getKeyInfo(bool checkValidity, KeyFormat keyFormat);
}
