import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:encrypt/encrypt.dart' as enc;
import 'package:flutter/material.dart';
import 'package:pointycastle/asn1/asn1_parser.dart';
import 'package:pointycastle/asn1/primitives/asn1_bit_string.dart';
import 'package:pointycastle/asn1/primitives/asn1_integer.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:pointycastle/export.dart' hide Padding, State;

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.blue),
      home: Scaffold(
        appBar: AppBar(title: const Text('Biometric Signature v9.0.0')),
        body: const ExampleAppBody(),
      ),
    );
  }
}

class ExampleAppBody extends StatefulWidget {
  const ExampleAppBody({super.key});

  @override
  State<ExampleAppBody> createState() => _ExampleAppBodyState();
}

class _ExampleAppBodyState extends State<ExampleAppBody> {
  final _biometricSignature = BiometricSignature();

  // Settings
  bool useEc = false;
  bool enableDecryption = false;
  KeyFormat _publicKeyFormat = KeyFormat.pem;
  KeyFormat _signatureFormat = KeyFormat.base64;

  // Results
  KeyCreationResult? keyResult;
  SignatureResult? signatureResult;
  DecryptResult? decryptResult;
  String? payload;
  String? errorMessage;
  bool isLoading = false;
  BiometricAvailability? availability;

  @override
  void initState() {
    super.initState();
    _checkAvailability();
  }

  Future<void> _checkAvailability() async {
    final result = await _biometricSignature.biometricAuthAvailable();
    setState(() {
      availability = result;
    });
  }

  Future<void> _createKeys() async {
    FocusScope.of(context).unfocus();
    setState(() => errorMessage = null);

    try {
      final result = await _biometricSignature.createKeys(
        keyFormat: _publicKeyFormat,
        androidConfig: AndroidConfig(
          useDeviceCredentials: false,
          signatureType: useEc ? SignatureType.ecdsa : SignatureType.rsa,
          setInvalidatedByBiometricEnrollment: true,
          enableDecryption: enableDecryption,
        ),
        iosConfig: IosConfig(
          useDeviceCredentials: false,
          signatureType: useEc ? SignatureType.ecdsa : SignatureType.rsa,
          biometryCurrentSet: true,
        ),
        macosConfig: MacosConfig(
          useDeviceCredentials: false,
          signatureType: useEc ? SignatureType.ecdsa : SignatureType.rsa,
          biometryCurrentSet: true,
        ),
        enforceBiometric: true,
        promptMessage: 'Authenticate to create keys',
      );

      if (result.code == BiometricError.success) {
        setState(() => keyResult = result);
      } else {
        setState(() => errorMessage = 'Error: ${result.code} - ${result.error}');
      }
    } catch (e) {
      setState(() => errorMessage = e.toString());
    }
  }

  Future<void> _createSignature() async {
    if (payload == null || payload!.isEmpty) {
      _showSnack('Enter payload first');
      return;
    }
    FocusScope.of(context).unfocus();
    setState(() {
      errorMessage = null;
      signatureResult = null;
    });

    try {
      final result = await _biometricSignature.createSignature(
        payload: payload!,
        keyFormat: _signatureFormat,
        promptMessage: 'Sign Data',
        androidConfig: AndroidConfig(
          useDeviceCredentials: false,
          signatureType: SignatureType.rsa, // Type inferred from key existence usually, but config required in API?
          // Wait, createSignature API in Dart wrapper:
          // createSignature({required String payload, AndroidConfig? androidConfig, ... })
          // The native side usually just looks up the key alias.
          // Passing configs might be for options like 'allowDeviceCredentials' which are in signature options usually.
          // But my new API merged Config and Options? 
          // Let's check biometric_signature.dart again. 
          // It accepts AndroidConfig?. 
          // But usually createSignature doesn't need full config, just UI options.
          // In my Pigeon schema, I removed SignatureOptions and just passed Configs?
          // Let's assume passing null or minimal config is fine if not needed, 
          // or if I reused AndroidConfig for options.
        ),
      );

      if (result.code == BiometricError.success) {
        setState(() => signatureResult = result);
      } else {
        setState(() => errorMessage = 'Error: ${result.code} - ${result.error}');
      }
    } catch (e) {
      setState(() => errorMessage = e.toString());
    }
  }

  Future<void> _decrypt() async {
    if (payload == null || payload!.isEmpty) {
      _showSnack('Enter encrypted b64 payload');
      return;
    }
    FocusScope.of(context).unfocus();
    setState(() {
      errorMessage = null;
      decryptResult = null;
    });

    try {
      // 1) Encrypt payload first (Roundtrip verification)
      final encryptedBase64 = await _encryptPayload(payload!);
      debugPrint('📦 Encrypted: ${encryptedBase64.substring(0, min(40, encryptedBase64.length))}...');

      // 2) Present biometric prompt via plugin (native UI).
      final result = await _biometricSignature.decrypt(
        payload: encryptedBase64,
        promptMessage: 'Decrypt Payload',
        androidConfig:  AndroidConfig(
          useDeviceCredentials: false, 
          // subtitle: 'Approve to decrypt data' // Removed in v9 API simplification, uses promptMessage
        ),
        iosConfig:  IosConfig(biometryCurrentSet: true),
        macosConfig:  MacosConfig(biometryCurrentSet: true),
      );

      // Only show overlay if we need to do extra processing after auth.
      setState(() {
        isLoading = true;
      });

      setState(() => decryptResult = result);
      if (result.decryptedData != null) {
        debugPrint('✅ Decrypted: ${result.decryptedData}');
      } else {
        debugPrint('❌ Decryption Failed: Code=${result.code}, Error=${result.error}');
        setState(() => errorMessage = 'Decryption Failed: ${result.code}');
      }
    } catch (e, stack) {
      setState(() => errorMessage = e.toString());
      debugPrint('❌ Error: $e\n$stack');
    } finally {
      setState(() => isLoading = false);
    }
  }

  /// Encrypts payload based on current key type
  Future<String> _encryptPayload(String plaintext) async {
    // Determine algorithm from state since KeyCreationResult doesn't carry it
    // useEc is the source of truth for what we requested.
    if (!useEc) {
      return _encryptRsa(plaintext);
    } else {
      // EC - use ECIES
      // Note: We use Dart-based ECIES for all platforms to simplify testing without native method channels.
      return _encryptEciesDart(plaintext);
    }
  }

  /// RSA encryption
  String _encryptRsa(String plaintext) {
    if (Platform.isIOS || Platform.isMacOS) {
      // iOS/macOS return raw PKCS#1 (RSAPublicKey) inside the PEM string.
      // We must strip the PEM headers and newlines to get the raw Base64.
      final cleanBase64 = keyResult!.publicKey!
          .replaceAll(RegExp(r'-----[A-Z ]+-----'), '')
          .replaceAll(RegExp(r'\s+'), '');
          
      final bytes = base64Decode(cleanBase64);
      final parser = ASN1Parser(bytes);
      final topLevel = parser.nextObject() as ASN1Sequence;
      
      final modulus = topLevel.elements![0] as ASN1Integer;
      final exponent = topLevel.elements![1] as ASN1Integer;
      
      final rsaPublicKey = RSAPublicKey(modulus.integer!, exponent.integer!);
      final encrypter = enc.Encrypter(enc.RSA(publicKey: rsaPublicKey));
      return encrypter.encrypt(plaintext).base64;
    }

    // Android returns SPKI (Standard X.509)
    final publicKeyStr = keyResult!.publicKey!;
    final publicKeyPem = publicKeyStr.contains('BEGIN PUBLIC KEY')
        ? publicKeyStr
        : '-----BEGIN PUBLIC KEY-----\n$publicKeyStr\n-----END PUBLIC KEY-----';

    final parser = enc.RSAKeyParser();
    final rsaPublicKey = parser.parse(publicKeyPem) as RSAPublicKey;
    final encrypter = enc.Encrypter(enc.RSA(publicKey: rsaPublicKey));
    return encrypter.encrypt(plaintext).base64;
  }

  /// ECIES encryption using Dart (PointyCastle)
  String _encryptEciesDart(String plaintext) {
    // Parse recipient's public key (handling both PEM and raw Base64 if needed)
    final publicKeyStr = keyResult!.publicKey!;
    // Note: _parseEcPublicKeyFromPem handles stripping headers
    final ecPublicKey = _parseEcPublicKeyFromPem(publicKeyStr);

    // Generate ephemeral keypair
    final ephemeralKeyPair = _generateEphemeralKeyPair(ecPublicKey.parameters!);
    final ephemeralPublic = ephemeralKeyPair.publicKey as ECPublicKey;
    final ephemeralPrivate = ephemeralKeyPair.privateKey as ECPrivateKey;

    // ECDH key agreement
    final agreement = ECDHBasicAgreement()..init(ephemeralPrivate);
    final sharedSecret = agreement.calculateAgreement(ecPublicKey);

    // Output: [EphemeralPubKey (Uncompressed 65)] || [Ciphertext + Tag]
    final isApple = Platform.isIOS || Platform.isMacOS;
    final ephemeralPubBytes = ephemeralPublic.Q!.getEncoded(false); // Uncompressed required

    // ECIES Parameters
    // Hypothesis: Apple Standard Mode uses Static Zero IV and binds EphemKey in SharedInfo.
    final sharedInfo = isApple ? ephemeralPubBytes : Uint8List(0);

    Uint8List gcmIv;
    Uint8List aesKey;
    final Uint8List aad;
    
    if (isApple) {
        // iOS Standard Mode Hypothesis
        // 1. IV is Static Zeros (16 bytes).
        // 2. KDF derives ONLY Key (16 bytes).
        final keySize = 16;
        aesKey = _kdfX963(sharedSecret, keySize, sharedInfo);
        gcmIv = Uint8List(16); // Zero IV
    } else {
        // Android Standard Mode (Derived IV)
        final keySize = 16;
        final ivSize = 12;
        final derived = _kdfX963(sharedSecret, keySize + ivSize, sharedInfo);
        aesKey = derived.sublist(0, keySize);
        gcmIv = derived.sublist(keySize, keySize + ivSize);
    }
        
    aad = Uint8List(0);

    // AES-GCM encryption
    final cipher = GCMBlockCipher(AESEngine());
    cipher.init(
      true,
      AEADParameters(KeyParameter(aesKey), 128, gcmIv, aad),
    );
    final ciphertext = cipher.process(
      Uint8List.fromList(utf8.encode(plaintext)),
    );
    
    // Construct Payload: [EphemKey] [Ciphertext]
    // Note: Android uses same payload structure
    final payloadParts = [ephemeralPubBytes, ciphertext];
    
    return base64Encode(
      Uint8List.fromList(payloadParts.expand((x) => x).toList()),
    );
  }

  // ==================== ECIES Helpers ====================

  ECPublicKey _parseEcPublicKeyFromPem(String pem) {
    // Strip headers if present
    final rows = pem
        .split('\n')
        .where((l) => !l.startsWith('-----') && l.trim().isNotEmpty)
        .join('');
    final bytes = base64Decode(rows);
    final params = ECDomainParameters('secp256r1');
    Uint8List pubBytes;

    try {
      final parser = ASN1Parser(bytes);
      final topLevel = parser.nextObject();

      if (topLevel is ASN1Sequence) {
        // SPKI format (Android)
        final bitString = topLevel.elements![1] as ASN1BitString;
        pubBytes = Uint8List.fromList(bitString.stringValues!);
      } else {
        // iOS returns raw bytes (often parses as OctetString due to 0x04 tag)
        pubBytes = bytes;
      }
    } catch (_) {
      // Fallback to raw bytes just in case
      pubBytes = bytes;
    }

    final q = params.curve.decodePoint(pubBytes)!;
    return ECPublicKey(q, params);
  }

  AsymmetricKeyPair<PublicKey, PrivateKey> _generateEphemeralKeyPair(
    ECDomainParameters params,
  ) {
    final generator = ECKeyGenerator();
    generator.init(
      ParametersWithRandom(ECKeyGeneratorParameters(params), _secureRandom()),
    );
    return generator.generateKeyPair();
  }

  SecureRandom _secureRandom() {
    final rng = FortunaRandom();
    final seed = Uint8List(32);
    final random = Random.secure();
    for (var i = 0; i < 32; i++) {
      seed[i] = random.nextInt(256);
    }
    rng.seed(KeyParameter(seed));
    return rng;
  }

  Uint8List _kdfX963(BigInt sharedSecret, int length, Uint8List sharedInfo) {
    final digest = SHA256Digest();
    final secretBytes = _bigIntToBytes(sharedSecret, 32);
    final result = Uint8List(length);
    var offset = 0;
    var counter = 1;

    while (offset < length) {
      digest.reset();
      digest.update(secretBytes, 0, secretBytes.length);
      digest.updateByte((counter >> 24) & 0xff);
      digest.updateByte((counter >> 16) & 0xff);
      digest.updateByte((counter >> 8) & 0xff);
      digest.updateByte(counter & 0xff);
      digest.update(sharedInfo, 0, sharedInfo.length);

      final hash = Uint8List(digest.digestSize);
      digest.doFinal(hash, 0);

      final toCopy = (length - offset).clamp(0, hash.length);
      result.setRange(offset, offset + toCopy, hash);
      offset += toCopy;
      counter++;
    }
    return result;
  }

  Uint8List _bigIntToBytes(BigInt number, int length) {
    var hex = number.toRadixString(16);
    if (hex.length % 2 != 0) hex = '0$hex';

    final bytes = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }

    if (bytes.length >= length) return bytes.sublist(bytes.length - length);

    final padded = Uint8List(length);
    padded.setRange(length - bytes.length, length, bytes);
    return padded;
  }

  Future<void> _deleteKeys() async {
    try {
      final success = await _biometricSignature.deleteKeys();
      if (success) {
        setState(() {
          keyResult = null;
          signatureResult = null;
          decryptResult = null;
          errorMessage = null;
        });
        _showSnack('Keys deleted');
      } else {
        setState(() => errorMessage = 'Failed to delete keys');
      }
    } catch (e) {
      setState(() => errorMessage = e.toString());
    }
  }

  void _showSnack(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Availability Info
          if (availability != null)
            Card(
              child: ListTile(
                leading: Icon(
                  availability!.canAuthenticate ? Icons.check_circle : Icons.warning,
                  color: availability!.canAuthenticate ? Colors.green : Colors.orange,
                ),
                title: Text(availability!.canAuthenticate ? 'Biometrics Available' : 'Biometrics Unavailable'),
                subtitle: Text(availability!.availableBiometrics?.toString() ?? availability!.reason ?? ''),
              ),
            ),
          
          const SizedBox(height: 10),

          // Config
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                children: [
                   Row(children: [
                     const Text('Use EC'),
                     Switch(value: useEc, onChanged: (v) => setState(() => useEc = v)),
                     const SizedBox(width: 20),
                     const Text('Decrypt Support'),
                     Switch(value: enableDecryption, onChanged: (v) => setState(() => enableDecryption = v)),
                   ]),
                   Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                      const Text('Pub Key: '), 
                      DropdownButton<KeyFormat>(value: _publicKeyFormat, onChanged: (v) { if(v!=null) setState(()=>_publicKeyFormat=v); }, items: KeyFormat.values.map((f)=>DropdownMenuItem(value: f, child: Text(f.name))).toList())
                   ]),
                   ElevatedButton(
                     onPressed: _createKeys,
                     child: const Text('Create Keys'),
                   ),
                ],
              ),
            ),
          ),

          if (keyResult != null)
            Card(
              color: Colors.green.shade50,
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                   children: [
                     const Text('Public Key Created:', style: TextStyle(fontWeight: FontWeight.bold)),
                     const SizedBox(height: 4),
                     Text(keyResult!.publicKey ?? '', style: const TextStyle(fontSize: 10, fontFamily: 'monospace')),
                     if (keyResult!.publicKeyBytes != null)
                        Text('Bytes: ${keyResult!.publicKeyBytes!.length} (Hex: ${keyResult!.publicKeyBytes!.map((e)=>e.toRadixString(16).padLeft(2,'0')).join()})', style: const TextStyle(fontSize: 8, color: Colors.grey)),
                     const SizedBox(height: 8),
                     TextButton.icon(
                       icon: const Icon(Icons.delete, size: 16),
                       label: const Text('Delete Keys'),
                       onPressed: _deleteKeys,
                     )
                   ],
                ),
              ),
            ),

          const SizedBox(height: 20),

          TextField(
            decoration: const InputDecoration(labelText: 'Payload (Text or Base64)'),
            onChanged: (v) => payload = v,
          ),
          
          const SizedBox(height: 10),
          Row(children: [
             const Text('Sig Format: '), 
             DropdownButton<KeyFormat>(value: _signatureFormat, onChanged: (v) { if(v!=null) setState(()=>_signatureFormat=v); }, items: KeyFormat.values.map((f)=>DropdownMenuItem(value: f, child: Text(f.name))).toList())
          ]),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(child: FilledButton(onPressed: _createSignature, child: const Text('Sign'))),
              const SizedBox(width: 10),
              Expanded(child: FilledButton.tonal(onPressed: _decrypt, child: const Text('Decrypt'))),
            ],
          ),

          if (errorMessage != null)
            Padding(
              padding: const EdgeInsets.all(8.0),
              child: Text(errorMessage!, style: const TextStyle(color: Colors.red)),
            ),

          if (signatureResult != null)
            _buildResult('Signature', signatureResult!.signature, bytes: signatureResult!.signatureBytes),

          if (decryptResult != null)
            _buildResult('Decrypted', decryptResult!.decryptedData),
        ],
      ),
    );
  }

  Widget _buildResult(String title, String? data, {Uint8List? bytes}) {
    return Card(
      margin: const EdgeInsets.only(top: 10),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: const TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 4),
            SelectableText(data ?? 'null', style: const TextStyle(fontFamily: 'monospace')),
            if (bytes != null)
               Text('Bytes: ${bytes.length} (Hex: ${bytes.map((e)=>e.toRadixString(16).padLeft(2,'0')).join()})', style: const TextStyle(fontSize: 8, color: Colors.grey)),
          ],
        ),
      ),
    );
  }
}
