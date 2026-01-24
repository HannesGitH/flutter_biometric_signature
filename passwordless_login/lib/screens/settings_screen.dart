import 'package:biometric_signature/biometric_signature.dart';
import 'package:flutter/material.dart';
import 'package:passwordless_login_example/models/user.dart';
import 'package:passwordless_login_example/screens/login_screen.dart';
import 'package:passwordless_login_example/services/auth_service.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final AuthService _authService = AuthService();
  User? _currentUser;
  KeyInfo? _keyInfo;
  BiometricAvailability? _availability;
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    setState(() => _isLoading = true);
    try {
      final user = await _authService.getCurrentUser();
      final keyInfo = await _authService.getKeyStatus();
      final availability = await _authService.getBiometricStatus();

      setState(() {
        _currentUser = user;
        _keyInfo = keyInfo;
        _availability = availability;
        _isLoading = false;
      });
    } catch (e) {
      setState(() => _isLoading = false);
      _showError(e.toString());
    }
  }

  Future<void> _testBiometric() async {
    if (_currentUser == null) return;

    try {
      final challenge =
          await _authService.requestChallenge(_currentUser!.username);
      final result = await _authService.authenticateWithChallenge(
        username: _currentUser!.username,
        challengeId: challenge.challengeId,
      );

      if (result.code == BiometricError.success) {
        _showSuccess('Biometric authentication successful!');
      } else {
        _showError('Authentication failed: ${result.error ?? result.code}');
      }
    } catch (e) {
      _showError(e.toString());
    }
  }

  Future<void> _reEnroll() async {
    if (_currentUser == null) return;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Re-enroll Biometrics'),
        content: const Text(
          'This will delete your current biometric keys and create new ones.\n\n'
          'You will be asked to authenticate to complete the process.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.orange),
            child: const Text('Re-enroll'),
          ),
        ],
      ),
    );

    if (confirmed != true) return;

    setState(() => _isLoading = true);
    try {
      await _authService.reEnrollBiometrics(_currentUser!.username);
      _showSuccess('Biometric re-enrollment successful!');
      await _loadData();
    } catch (e) {
      _showError('Re-enrollment failed: $e');
      setState(() => _isLoading = false);
    }
  }

  Future<void> _deleteAccount() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete Account'),
        content: const Text(
          'This will permanently delete your account and biometric keys.\n\n'
          'This action cannot be undone!',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            child: const Text('Delete'),
          ),
        ],
      ),
    );

    if (confirmed != true || !mounted) return;

    try {
      await _authService.deleteKeys();
      await _authService.logout();

      if (mounted) {
        Navigator.of(context).pushAndRemoveUntil(
          MaterialPageRoute(builder: (context) => const LoginScreen()),
          (route) => false,
        );
      }
    } catch (e) {
      _showError('Failed to delete account: $e');
    }
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: Colors.red),
    );
  }

  void _showSuccess(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: Colors.green),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return Scaffold(
        appBar: AppBar(title: const Text('Settings')),
        body: const Center(child: CircularProgressIndicator()),
      );
    }

    if (_currentUser == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Settings')),
        body: const Center(child: Text('User not found')),
      );
    }

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Account Info
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Account',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  const Divider(height: 24),
                  _buildInfoRow('Username', _currentUser!.username),
                  _buildInfoRow('Email', _currentUser!.email),
                  if (_currentUser!.lastReEnrollment != null)
                    _buildInfoRow(
                      'Last Re-enrollment',
                      _formatDateTime(_currentUser!.lastReEnrollment!),
                    ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Biometric Status
          Card(
            color: _availability?.canAuthenticate == true
                ? Colors.green.withOpacity(0.1)
                : Colors.orange.withOpacity(0.1),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Biometric Status',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  const Divider(height: 24),
                  Row(
                    children: [
                      Icon(
                        _availability?.canAuthenticate == true
                            ? Icons.check_circle
                            : Icons.warning,
                        color: _availability?.canAuthenticate == true
                            ? Colors.green
                            : Colors.orange,
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          _availability?.canAuthenticate == true
                              ? 'Biometrics Available'
                              : 'Biometrics Unavailable',
                          style: const TextStyle(fontWeight: FontWeight.w500),
                        ),
                      ),
                    ],
                  ),
                  if (_availability?.availableBiometrics != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      'Available: ${_availability!.availableBiometrics!.map((e) => e.toString().split('.').last).join(', ')}',
                      style: TextStyle(fontSize: 12, color: Colors.grey[700]),
                    ),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Key Status
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Key Status',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  const Divider(height: 24),
                  _buildStatusRow(
                    'Key Exists',
                    _keyInfo?.exists == true ? 'Yes' : 'No',
                    _keyInfo?.exists == true,
                  ),
                  _buildStatusRow(
                    'Key Valid',
                    _keyInfo?.isValid == true ? 'Yes' : 'Unknown',
                    _keyInfo?.isValid,
                  ),
                  if (_keyInfo?.algorithm != null)
                    _buildInfoRow('Algorithm', _keyInfo!.algorithm!),
                  if (_keyInfo?.keySize != null)
                    _buildInfoRow('Key Size', '${_keyInfo!.keySize} bits'),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Configuration
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Configuration',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  const Divider(height: 24),
                  _buildStatusRow(
                    'Device Credentials',
                    _currentUser!.allowDeviceCredentials
                        ? 'Enabled'
                        : 'Disabled',
                    _currentUser!.allowDeviceCredentials,
                  ),
                  _buildStatusRow(
                    'Invalidate on Changes',
                    _currentUser!.keyInvalidatedOnEnrollmentChange
                        ? 'Yes'
                        : 'No',
                    _currentUser!.keyInvalidatedOnEnrollmentChange,
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 24),

          // Actions
          const Text(
            'Actions',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 12),
          ElevatedButton.icon(
            onPressed: _testBiometric,
            icon: const Icon(Icons.fingerprint),
            label: const Text('Test Biometric'),
            style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
          ),
          const SizedBox(height: 12),
          OutlinedButton.icon(
            onPressed: _reEnroll,
            icon: const Icon(Icons.refresh),
            label: const Text('Re-enroll Biometrics'),
            style: OutlinedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
          ),
          const SizedBox(height: 12),
          OutlinedButton.icon(
            onPressed: _deleteAccount,
            icon: const Icon(Icons.delete_forever),
            label: const Text('Delete Account'),
            style: OutlinedButton.styleFrom(
              foregroundColor: Colors.red,
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
          ),
          const SizedBox(height: 24),

          // Info box
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.blue.withOpacity(0.1),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.blue.withOpacity(0.3)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Row(
                  children: [
                    Icon(Icons.info_outline, size: 20, color: Colors.blue),
                    SizedBox(width: 8),
                    Text(
                      'About Biometric Keys',
                      style: TextStyle(fontWeight: FontWeight.w500),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Text(
                  'Your biometric keys are stored securely in hardware (Secure Enclave/StrongBox) '
                  'and never leave your device. Re-enrollment creates new keys if your current keys '
                  'become invalidated.',
                  style: TextStyle(fontSize: 12, color: Colors.grey[700]),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 140,
            child: Text(
              '$label:',
              style: TextStyle(color: Colors.grey[700]),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(fontWeight: FontWeight.w500),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatusRow(String label, String value, bool? isGood) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        children: [
          if (isGood != null)
            Icon(
              isGood ? Icons.check_circle : Icons.cancel,
              size: 18,
              color: isGood ? Colors.green : Colors.orange,
            ),
          if (isGood != null) const SizedBox(width: 8),
          Expanded(child: Text(label)),
          Text(
            value,
            style: TextStyle(
              fontWeight: FontWeight.w500,
              color: isGood == true
                  ? Colors.green
                  : isGood == false
                      ? Colors.orange
                      : null,
            ),
          ),
        ],
      ),
    );
  }

  String _formatDateTime(DateTime dateTime) {
    return '${dateTime.year}-${dateTime.month.toString().padLeft(2, '0')}-'
        '${dateTime.day.toString().padLeft(2, '0')} '
        '${dateTime.hour.toString().padLeft(2, '0')}:'
        '${dateTime.minute.toString().padLeft(2, '0')}';
  }
}
