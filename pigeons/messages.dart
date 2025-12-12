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
  String? error;
  BiometricError? code;
}

class SignatureResult {
  String? signature;
  String? publicKey;
  String? error;
  BiometricError? code;
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

/// Configuration for Android.
class AndroidConfig {
  bool? useDeviceCredentials;
  bool? setInvalidatedByBiometricEnrollment;
  bool? enableDecryption;
  SignatureType? signatureType;
  String? promptTitle;
  String? promptSubtitle;
  String? promptDescription;
  String? cancelButtonText;
}

/// Configuration for iOS.
class IosConfig {
  bool? useDeviceCredentials;
  bool? biometryCurrentSet;
  SignatureType? signatureType;
  String? localizedReason;
  bool? shouldMigrate;
}

/// Configuration for macOS.
class MacosConfig {
  bool? useDeviceCredentials;
  bool? biometryCurrentSet;
  SignatureType? signatureType;
  String? localizedReason;
}

enum KeyFormat {
  base64,
  pem,
}

@HostApi()
abstract class BiometricSignatureApi {
  /// Checks if biometric authentication is available.
  BiometricAvailability getBiometricAvailability();

  /// Creates a new key pair.
  @async
  KeyCreationResult createKeys(
      AndroidConfig? androidConfig,
      IosConfig? iosConfig,
      MacosConfig? macosConfig,
      KeyFormat keyFormat,
      bool enforceBiometric,
      String? promptMessage);

  /// Creates a signature.
  @async
  SignatureResult createSignature(
      String? payload,
      AndroidConfig? androidConfig,
      IosConfig? iosConfig,
      MacosConfig? macosConfig,
      String? promptMessage);

  /// Decrypts data.
  @async
  DecryptResult decrypt(
      String? payload,
      AndroidConfig? androidConfig,
      IosConfig? iosConfig,
      MacosConfig? macosConfig,
      String? promptMessage);

  /// Deletes keys.
  bool deleteKeys();

  /// Checks if a key exists.
  @async
  bool biometricKeyExists(bool checkValidity);
}
