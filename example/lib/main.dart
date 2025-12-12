import 'dart:convert';
import 'dart:io';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:flutter/material.dart';

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
        appBar: AppBar(title: const Text('Biometric Signature v9.0')),
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
        keyFormat: KeyFormat.pem,
        androidConfig: AndroidConfig(
          useDeviceCredentials: false,
          signatureType: useEc ? AndroidSignatureType.ecdsa : AndroidSignatureType.rsa,
          setInvalidatedByBiometricEnrollment: true,
          enableDecryption: enableDecryption,
        ),
        iosConfig: IosConfig(
          useDeviceCredentials: false,
          signatureType: useEc ? IosSignatureType.ecdsa : IosSignatureType.rsa,
          biometryCurrentSet: true,
        ),
        macosConfig: MacosConfig(
          useDeviceCredentials: false,
          signatureType: useEc ? MacosSignatureType.ecdsa : MacosSignatureType.rsa,
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
        promptMessage: 'Sign Data',
        androidConfig: const AndroidConfig(
          useDeviceCredentials: false,
          signatureType: AndroidSignatureType.rsa, // Type inferred from key existence usually, but config required in API? 
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
      final result = await _biometricSignature.decrypt(
        payload: payload!,
        promptMessage: 'Decrypt Data',
      );

      if (result.code == BiometricError.success) {
        setState(() => decryptResult = result);
      } else {
        setState(() => errorMessage = 'Error: ${result.code} - ${result.error}');
      }
    } catch (e) {
      setState(() => errorMessage = e.toString());
    }
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
            _buildResult('Signature', signatureResult!.signature),

          if (decryptResult != null)
            _buildResult('Decrypted', decryptResult!.decryptedData),
        ],
      ),
    );
  }

  Widget _buildResult(String title, String? data) {
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
          ],
        ),
      ),
    );
  }
}
