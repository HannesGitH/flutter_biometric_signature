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
    cppSourceOut: 'windows/messages.g.cpp',
    cppHeaderOut: 'windows/messages.g.h',
    cppOptions: CppOptions(namespace: 'biometric_signature'),
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

/// Configuration for key creation (all platforms).
///
/// Fields are documented with which platform(s) they apply to.
/// Windows ignores most fields as it only supports RSA with mandatory
/// Windows Hello authentication.
class CreateKeysConfig {
  // === Cross-platform options (availability varies by platform) ===

  /// [Android/iOS/macOS] The cryptographic algorithm to use.
  /// Windows only supports RSA and ignores this field.
  SignatureType? signatureType;

  /// [Android/iOS/macOS] Whether to require biometric authentication
  /// during key creation. Windows always authenticates via Windows Hello.
  bool? enforceBiometric;

  /// [Android/iOS/macOS] Whether to invalidate the key when new biometrics
  /// are enrolled. Not supported on Windows.
  ///
  /// **Security Note**: When `true`, keys become invalid if fingerprints/faces
  /// are added or removed, preventing unauthorized access if an attacker
  /// enrolls their own biometrics on a compromised device.
  bool? setInvalidatedByBiometricEnrollment;

  /// [Android/iOS/macOS] Whether to allow device credentials (PIN/pattern/passcode)
  /// as fallback for biometric authentication. Not supported on Windows.
  bool? useDeviceCredentials;

  /// [Android] Whether to enable decryption capability for the key.
  /// On iOS/macOS, decryption is always available with EC keys.
  bool? enableDecryption;

  // === Android prompt customization ===

  /// [Android] Subtitle text for the biometric prompt.
  String? promptSubtitle;

  /// [Android] Description text for the biometric prompt.
  String? promptDescription;

  /// [Android] Text for the cancel button in the biometric prompt.
  String? cancelButtonText;
}

/// Configuration for signature creation (all platforms).
///
/// Fields are documented with which platform(s) they apply to.
class CreateSignatureConfig {
  // === Android prompt customization ===

  /// [Android] Subtitle text for the biometric prompt.
  String? promptSubtitle;

  /// [Android] Description text for the biometric prompt.
  String? promptDescription;

  /// [Android] Text for the cancel button in the biometric prompt.
  String? cancelButtonText;

  /// [Android] Whether to allow device credentials (PIN/pattern) as fallback.
  bool? allowDeviceCredentials;

  // === iOS options ===

  /// [iOS] Whether to migrate from legacy keychain storage.
  bool? shouldMigrate;
}

/// Configuration for decryption (all platforms).
///
/// Fields are documented with which platform(s) they apply to.
/// Note: Decryption is not supported on Windows.
class DecryptConfig {
  // === Android prompt customization ===

  /// [Android] Subtitle text for the biometric prompt.
  String? promptSubtitle;

  /// [Android] Description text for the biometric prompt.
  String? promptDescription;

  /// [Android] Text for the cancel button in the biometric prompt.
  String? cancelButtonText;

  /// [Android] Whether to allow device credentials (PIN/pattern) as fallback.
  bool? allowDeviceCredentials;

  // === iOS options ===

  /// [iOS] Whether to migrate from legacy keychain storage.
  bool? shouldMigrate;
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
  @async
  BiometricAvailability biometricAuthAvailable();

  /// Creates a new key pair.
  ///
  /// [config] contains platform-specific options. See [CreateKeysConfig].
  /// [keyFormat] specifies the output format for the public key.
  /// [promptMessage] is the message shown to the user during authentication.
  @async
  KeyCreationResult createKeys(
    CreateKeysConfig? config,
    KeyFormat keyFormat,
    String? promptMessage,
  );

  /// Creates a signature.
  ///
  /// [payload] is the data to sign.
  /// [config] contains platform-specific options. See [CreateSignatureConfig].
  /// [signatureFormat] specifies the output format for the signature.
  /// [keyFormat] specifies the output format for the public key.
  /// [promptMessage] is the message shown to the user during authentication.
  @async
  SignatureResult createSignature(
    String payload,
    CreateSignatureConfig? config,
    SignatureFormat signatureFormat,
    KeyFormat keyFormat,
    String? promptMessage,
  );

  /// Decrypts data.
  ///
  /// Note: Not supported on Windows.
  /// [payload] is the encrypted data.
  /// [payloadFormat] specifies the format of the encrypted data.
  /// [config] contains platform-specific options. See [DecryptConfig].
  /// [promptMessage] is the message shown to the user during authentication.
  @async
  DecryptResult decrypt(
    String payload,
    PayloadFormat payloadFormat,
    DecryptConfig? config,
    String? promptMessage,
  );

  /// Deletes keys.
  @async
  bool deleteKeys();

  /// Gets detailed information about existing biometric keys.
  ///
  /// Returns key metadata including algorithm, size, validity, and public keys.
  @async
  KeyInfo getKeyInfo(bool checkValidity, KeyFormat keyFormat);
}
