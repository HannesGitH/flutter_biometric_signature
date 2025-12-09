// ignore_for_file: constant_identifier_names
/// Supported signature algorithms on macOS.
enum MacosSignatureType { RSA, ECDSA }

/// Convenience helpers for [MacosSignatureType].
extension MacosSignatureTypeExtension on MacosSignatureType {
  /// Returns `true` when the ECDSA algorithm is selected.
  bool get isEc => this == MacosSignatureType.ECDSA;
}

/// macOS-specific configuration for enrolling or using biometric keys.
class MacosConfig {
  /// Whether device credentials (passcode) can unlock the key instead of
  /// biometrics.
  bool useDeviceCredentials;

  /// Key algorithm to use when creating a signature.
  MacosSignatureType signatureType;

  /// Whether to constraint Key usage for current biometric enrollment.
  bool biometryCurrentSet;

  /// Creates a new macOS configuration.
  MacosConfig({
    required this.useDeviceCredentials,
    this.signatureType = MacosSignatureType.RSA,
    this.biometryCurrentSet = true,
  });
}
