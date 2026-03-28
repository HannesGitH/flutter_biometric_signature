import 'dart:io';

import 'package:biometric_signature/biometric_signature.dart';
import 'package:flutter/material.dart';
import 'package:passwordless_login_example/screens/home_screen.dart';
import 'package:passwordless_login_example/services/auth_service.dart';

class RegisterScreen extends StatefulWidget {
  const RegisterScreen({super.key});

  @override
  State<RegisterScreen> createState() => _RegisterScreenState();
}

class _RegisterScreenState extends State<RegisterScreen> {
  final AuthService _authService = AuthService();
  final _formKey = GlobalKey<FormState>();
  final _usernameController = TextEditingController();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _confirmPasswordController = TextEditingController();
  bool _isLoading = false;
  bool _allowDeviceCredentials = false;
  bool _keyInvalidatedOnEnrollmentChange = true;
  bool _obscurePassword = true;
  bool _obscureConfirmPassword = true;

  @override
  void dispose() {
    _usernameController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  Future<void> _register() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() => _isLoading = true);

    try {
      final username = _usernameController.text.trim();
      final email = _emailController.text.trim();

      // Check biometric availability first
      final availability = await _authService.getBiometricStatus();
      if (!(availability.canAuthenticate ?? false)) {
        _showError(
          'Biometric authentication is not available on this device${availability.reason != null ? ': ${availability.reason}' : ''}',
        );
        setState(() => _isLoading = false);
        return;
      }

      if (!(availability.hasEnrolledBiometrics ?? false)) {
        _showError(
          'No biometrics are enrolled. Please enroll fingerprint or face in device settings.',
        );
        setState(() => _isLoading = false);
        return;
      }

      // Check username availability
      final isAvailable = await _authService.isUsernameAvailable(username);
      if (!isAvailable) {
        throw Exception('Username already taken');
      }

      // Show biometric consent
      final confirmed = await _showBiometricConsent();
      if (!confirmed) {
        setState(() => _isLoading = false);
        return;
      }

      // Register user (this will trigger biometric enrollment)
      final user = await _authService.register(
        username: username,
        email: email,
        allowDeviceCredentials: _allowDeviceCredentials,
        keyInvalidatedOnEnrollmentChange: _keyInvalidatedOnEnrollmentChange,
      );

      // Store backup password (Android only, optional)
      final password = _passwordController.text;
      if (Platform.isAndroid && password.isNotEmpty) {
        await _authService.setPassword(user.id, password);
      }

      // Auto-login after registration
      List<BiometricFallbackOption>? fallbackOptions;
      if (Platform.isAndroid && password.isNotEmpty) {
        fallbackOptions = [
          BiometricFallbackOption(text: 'Use Password', iconName: 'password'),
        ];
      }

      final challenge = await _authService.requestChallenge(username);
      final result = await _authService.authenticateWithChallenge(
        username: username,
        challengeId: challenge.challengeId,
        fallbackOptions: fallbackOptions,
      );

      if (result.code == BiometricError.fallbackSelected) {
        setState(() => _isLoading = false);
        if (mounted) {
          await _showPasswordDialog(username);
        }
        return;
      }

      if (result.code != BiometricError.success) {
        throw Exception(
          'Authentication failed: ${result.error ?? result.code}',
        );
      }

      await _authService.createSession(username);

      if (mounted) {
        // Success - navigate to home
        Navigator.of(context).pushAndRemoveUntil(
          MaterialPageRoute(builder: (context) => const HomeScreen()),
          (route) => false,
        );
      }
    } on Exception catch (e) {
      _showError(e.toString().replaceFirst('Exception: ', ''));
      setState(() => _isLoading = false);
    } catch (e) {
      _showError(e.toString());
      setState(() => _isLoading = false);
    }
  }

  Future<bool> _showBiometricConsent() async {
    final result = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Enable Biometric Login'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'To complete registration, we need to set up biometric authentication.',
              ),
              const SizedBox(height: 16),
              const Text('This will:'),
              const SizedBox(height: 8),
              const Row(
                children: [
                  Icon(Icons.check, size: 16, color: Colors.green),
                  SizedBox(width: 8),
                  Expanded(child: Text('Generate secure keys on your device')),
                ],
              ),
              const SizedBox(height: 4),
              const Row(
                children: [
                  Icon(Icons.check, size: 16, color: Colors.green),
                  SizedBox(width: 8),
                  Expanded(child: Text('Never send biometric data to server')),
                ],
              ),
              const SizedBox(height: 4),
              const Row(
                children: [
                  Icon(Icons.check, size: 16, color: Colors.green),
                  SizedBox(width: 8),
                  Expanded(child: Text('Enable passwordless login')),
                ],
              ),
              const SizedBox(height: 16),
              const Divider(),
              const SizedBox(height: 8),
              const Text(
                'Configuration:',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Icon(
                    _allowDeviceCredentials ? Icons.check_circle : Icons.cancel,
                    size: 16,
                    color: _allowDeviceCredentials ? Colors.green : Colors.grey,
                  ),
                  const SizedBox(width: 8),
                  const Expanded(child: Text('Device credential fallback')),
                ],
              ),
              const SizedBox(height: 4),
              Row(
                children: [
                  Icon(
                    _keyInvalidatedOnEnrollmentChange
                        ? Icons.check_circle
                        : Icons.cancel,
                    size: 16,
                    color: _keyInvalidatedOnEnrollmentChange
                        ? Colors.green
                        : Colors.grey,
                  ),
                  const SizedBox(width: 8),
                  const Expanded(
                    child: Text('Invalidate on biometric changes'),
                  ),
                ],
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Continue'),
          ),
        ],
      ),
    );

    return result ?? false;
  }

  Future<void> _showPasswordDialog(String username) async {
    final passwordController = TextEditingController();
    String? errorText;
    bool obscure = true;

    final authenticated = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: const Row(
            children: [
              Icon(Icons.lock, color: Colors.blue),
              SizedBox(width: 12),
              Text('Enter Password'),
            ],
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text('Enter your backup password to complete login.'),
              const SizedBox(height: 16),
              TextField(
                controller: passwordController,
                obscureText: obscure,
                autofocus: true,
                onSubmitted: (_) async {
                  final isValid = await _authService.verifyPasswordByUsername(
                    username,
                    passwordController.text,
                  );
                  if (isValid) {
                    Navigator.pop(dialogContext, true);
                  } else {
                    setDialogState(() => errorText = 'Incorrect password');
                  }
                },
                decoration: InputDecoration(
                  labelText: 'Password',
                  prefixIcon: const Icon(Icons.lock_outline),
                  errorText: errorText,
                  suffixIcon: IconButton(
                    icon:
                        Icon(obscure ? Icons.visibility : Icons.visibility_off),
                    onPressed: () => setDialogState(() => obscure = !obscure),
                  ),
                ),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext, false),
              child: const Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: () async {
                final isValid = await _authService.verifyPasswordByUsername(
                  username,
                  passwordController.text,
                );
                if (isValid) {
                  Navigator.pop(dialogContext, true);
                } else {
                  setDialogState(() => errorText = 'Incorrect password');
                }
              },
              child: const Text('Login'),
            ),
          ],
        ),
      ),
    );

    if (authenticated != true || !mounted) return;

    try {
      await _authService.createSession(username);
      if (mounted) {
        Navigator.of(context).pushAndRemoveUntil(
          MaterialPageRoute(builder: (context) => const HomeScreen()),
          (route) => false,
        );
      }
    } catch (e) {
      if (mounted) _showError('Login failed: $e');
    }
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), backgroundColor: Colors.red),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Create Account')),
      body: SafeArea(
        child: Form(
          key: _formKey,
          child: ListView(
            padding: const EdgeInsets.all(24),
            children: [
              const Text(
                'Register',
                style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              Text(
                'Create a passwordless account',
                style: TextStyle(fontSize: 16, color: Colors.grey[600]),
              ),
              const SizedBox(height: 32),
              TextFormField(
                controller: _usernameController,
                decoration: const InputDecoration(
                  labelText: 'Username',
                  prefixIcon: Icon(Icons.person),
                ),
                enabled: !_isLoading,
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return 'Username is required';
                  }
                  if (value.length < 3) {
                    return 'Username must be at least 3 characters';
                  }
                  return null;
                },
              ),
              const SizedBox(height: 16),
              TextFormField(
                controller: _emailController,
                decoration: const InputDecoration(
                  labelText: 'Email',
                  prefixIcon: Icon(Icons.email),
                ),
                keyboardType: TextInputType.emailAddress,
                enabled: !_isLoading,
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return 'Email is required';
                  }
                  if (!value.contains('@')) {
                    return 'Please enter a valid email';
                  }
                  return null;
                },
              ),
              if (Platform.isAndroid) ...[
                const SizedBox(height: 24),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Colors.orange.withOpacity(0.05),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: Colors.orange.withOpacity(0.3)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Row(
                        children: [
                          Icon(Icons.lock_outline,
                              size: 20, color: Colors.orange),
                          SizedBox(width: 8),
                          Text(
                            'Backup Password (optional)',
                            style: TextStyle(fontWeight: FontWeight.bold),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'On Android 15+, a "Use Password" button will appear on the biometric prompt so you can log in even if biometrics fail.',
                        style: TextStyle(fontSize: 12, color: Colors.grey[700]),
                      ),
                      const SizedBox(height: 16),
                      TextFormField(
                        controller: _passwordController,
                        obscureText: _obscurePassword,
                        enabled: !_isLoading,
                        decoration: InputDecoration(
                          labelText: 'Password',
                          prefixIcon: const Icon(Icons.key),
                          suffixIcon: IconButton(
                            icon: Icon(_obscurePassword
                                ? Icons.visibility
                                : Icons.visibility_off),
                            onPressed: () => setState(
                              () => _obscurePassword = !_obscurePassword,
                            ),
                          ),
                        ),
                        validator: (value) {
                          if (value != null &&
                              value.isNotEmpty &&
                              value.length < 8) {
                            return 'Password must be at least 8 characters';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 12),
                      TextFormField(
                        controller: _confirmPasswordController,
                        obscureText: _obscureConfirmPassword,
                        enabled: !_isLoading,
                        decoration: InputDecoration(
                          labelText: 'Confirm Password',
                          prefixIcon: const Icon(Icons.key),
                          suffixIcon: IconButton(
                            icon: Icon(_obscureConfirmPassword
                                ? Icons.visibility
                                : Icons.visibility_off),
                            onPressed: () => setState(
                              () => _obscureConfirmPassword =
                                  !_obscureConfirmPassword,
                            ),
                          ),
                        ),
                        validator: (value) {
                          if (_passwordController.text.isNotEmpty &&
                              value != _passwordController.text) {
                            return 'Passwords do not match';
                          }
                          return null;
                        },
                      ),
                    ],
                  ),
                ),
              ],
              const SizedBox(height: 24),
              Card(
                color: Colors.blue.withOpacity(0.05),
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Security Options',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                        ),
                      ),
                      const SizedBox(height: 16),
                      SwitchListTile(
                        value: _allowDeviceCredentials,
                        onChanged: _isLoading
                            ? null
                            : (v) =>
                                setState(() => _allowDeviceCredentials = v),
                        title: const Text('Allow Device Credentials'),
                        subtitle: const Text(
                          'Allow using PIN/pattern/passcode as fallback',
                          style: TextStyle(fontSize: 12),
                        ),
                        contentPadding: EdgeInsets.zero,
                      ),
                      const SizedBox(height: 8),
                      SwitchListTile(
                        value: _keyInvalidatedOnEnrollmentChange,
                        onChanged: _isLoading
                            ? null
                            : (v) => setState(
                                  () => _keyInvalidatedOnEnrollmentChange = v,
                                ),
                        title: const Text('Invalidate on Biometric Changes'),
                        subtitle: const Text(
                          'Require re-enrollment if new biometrics are added (recommended)',
                          style: TextStyle(fontSize: 12),
                        ),
                        contentPadding: EdgeInsets.zero,
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 24),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: _isLoading ? null : _register,
                  child: _isLoading
                      ? const SizedBox(
                          height: 20,
                          width: 20,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Text('Register', style: TextStyle(fontSize: 16)),
                ),
              ),
              const SizedBox(height: 24),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.green.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: Colors.green.withOpacity(0.3)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Row(
                      children: [
                        Icon(Icons.info_outline, size: 20, color: Colors.green),
                        SizedBox(width: 8),
                        Text(
                          'No Password Required',
                          style: TextStyle(fontWeight: FontWeight.w500),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'You\'ll use your fingerprint or face to login. '
                      'It\'s more secure and convenient than passwords.',
                      style: TextStyle(fontSize: 12, color: Colors.grey[700]),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
