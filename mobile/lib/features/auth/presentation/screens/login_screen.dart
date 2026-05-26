import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/config/app_config.dart';
import '../../../../core/localization/app_localizations.dart';
import '../../../../core/network/error_messages.dart';
import '../providers/auth_provider.dart';

class LoginScreen extends ConsumerStatefulWidget {
  const LoginScreen({super.key});

  @override
  ConsumerState<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends ConsumerState<LoginScreen> {
  final _formKey = GlobalKey<FormState>();
  final _phone = TextEditingController();
  final _password = TextEditingController();
  bool _busy = false;
  String? _error;
  bool _hidePassword = true;

  @override
  void dispose() {
    _phone.dispose();
    _password.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref.read(authProvider.notifier).login(
            phone: _phone.text.trim(),
            password: _password.text,
          );
    } catch (e) {
      if (!mounted) return;
      final message = localiseError(context, e);
      setState(() => _error = message);
      showErrorSnackBar(context, e);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
          child: Form(
            key: _formKey,
            child: ListView(
              children: [
                const SizedBox(height: 32),
                Icon(Icons.cleaning_services_rounded,
                    size: 56, color: theme.colorScheme.primary),
                const SizedBox(height: 16),
                Text(l10n.t('auth.welcomeBack'),
                    textAlign: TextAlign.center,
                    style: theme.textTheme.headlineMedium),
                const SizedBox(height: 4),
                Text(l10n.t('auth.loginSubtitle'),
                    textAlign: TextAlign.center,
                    style: theme.textTheme.bodyMedium),
                const SizedBox(height: 32),
                TextFormField(
                  controller: _phone,
                  keyboardType: TextInputType.phone,
                  decoration: InputDecoration(
                    labelText: l10n.t('auth.phone'),
                    prefixIcon: const Icon(Icons.phone_outlined),
                  ),
                  validator: (v) {
                    final s = (v ?? '').trim();
                    if (s.length < 6) return l10n.t('auth.invalidPhone');
                    return null;
                  },
                ),
                const SizedBox(height: 16),
                TextFormField(
                  controller: _password,
                  obscureText: _hidePassword,
                  decoration: InputDecoration(
                    labelText: l10n.t('auth.password'),
                    prefixIcon: const Icon(Icons.lock_outline),
                    suffixIcon: IconButton(
                      icon: Icon(_hidePassword
                          ? Icons.visibility_outlined
                          : Icons.visibility_off_outlined),
                      onPressed: () =>
                          setState(() => _hidePassword = !_hidePassword),
                    ),
                  ),
                  validator: (v) {
                    final s = v ?? '';
                    if (s.length < 8) return l10n.t('auth.passwordTooShort');
                    return null;
                  },
                ),
                if (_error != null) ...[
                  const SizedBox(height: 12),
                  Text(_error!,
                      style: TextStyle(color: theme.colorScheme.error)),
                ],
                const SizedBox(height: 24),
                FilledButton(
                  onPressed: _busy ? null : _submit,
                  child: _busy
                      ? const SizedBox(
                          height: 22,
                          width: 22,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : Text(l10n.t('auth.login')),
                ),
                const SizedBox(height: 8),
                TextButton(
                  onPressed: _busy ? null : () => context.go('/register'),
                  child: Text(
                    '${l10n.t('auth.noAccount')} ${l10n.t('auth.register')}',
                  ),
                ),
                TextButton(
                  onPressed:
                      _busy ? null : () => context.push('/forgot-password'),
                  child: Text(l10n.t('auth.forgotPassword')),
                ),
                const SizedBox(height: 16),
                Text(
                  l10n.t('network.serverBaseUrl',
                      args: {'url': AppConfig.apiBaseUrl}),
                  textAlign: TextAlign.center,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.outline,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
