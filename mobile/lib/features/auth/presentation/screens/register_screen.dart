import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/network/error_messages.dart';
import '../providers/auth_provider.dart';

class RegisterScreen extends ConsumerStatefulWidget {
  const RegisterScreen({super.key});

  @override
  ConsumerState<RegisterScreen> createState() => _RegisterScreenState();
}

class _RegisterScreenState extends ConsumerState<RegisterScreen> {
  final _formKey = GlobalKey<FormState>();
  final _phone = TextEditingController();
  final _name = TextEditingController();
  final _password = TextEditingController();
  final _address = TextEditingController();
  bool _busy = false;
  bool _hidePassword = true;
  String? _error;

  @override
  void dispose() {
    _phone.dispose();
    _name.dispose();
    _password.dispose();
    _address.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final locale = Localizations.localeOf(context).languageCode;
      await ref.read(authProvider.notifier).register(
            phone: _phone.text.trim(),
            fullName: _name.text.trim(),
            password: _password.text,
            address: _address.text.trim().isEmpty ? null : _address.text.trim(),
            locale: locale,
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
      appBar: AppBar(title: Text(l10n.t('auth.register'))),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
          child: Form(
            key: _formKey,
            child: ListView(
              children: [
                const SizedBox(height: 8),
                Text(l10n.t('auth.createAccountSubtitle'),
                    style: theme.textTheme.bodyMedium),
                const SizedBox(height: 24),
                TextFormField(
                  controller: _name,
                  textCapitalization: TextCapitalization.words,
                  decoration: InputDecoration(
                    labelText: l10n.t('auth.fullName'),
                    prefixIcon: const Icon(Icons.person_outline),
                  ),
                  validator: (v) =>
                      (v ?? '').trim().isEmpty ? l10n.t('auth.nameRequired') : null,
                ),
                const SizedBox(height: 16),
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
                const SizedBox(height: 16),
                TextFormField(
                  controller: _address,
                  decoration: InputDecoration(
                    labelText: l10n.t('auth.address'),
                    prefixIcon: const Icon(Icons.home_outlined),
                  ),
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
                      : Text(l10n.t('auth.register')),
                ),
                const SizedBox(height: 8),
                TextButton(
                  onPressed: _busy ? null : () => context.go('/login'),
                  child: Text(
                    '${l10n.t('auth.alreadyHaveAccount')} ${l10n.t('auth.login')}',
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
