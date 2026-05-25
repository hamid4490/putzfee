import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/theme/app_theme.dart';
import '../../../auth/presentation/providers/auth_provider.dart';

class ProfileScreen extends ConsumerWidget {
  const ProfileScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    final user = ref.watch(authProvider).user;
    final mode = ref.watch(themeModeProvider);
    final localeNotifier = ref.read(localeProvider.notifier);
    final currentLocale = Localizations.localeOf(context);

    return Scaffold(
      appBar: AppBar(title: Text(l10n.t('profile.title'))),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  CircleAvatar(
                    radius: 32,
                    backgroundColor:
                        theme.colorScheme.primary.withValues(alpha: 0.15),
                    child: Icon(Icons.person, color: theme.colorScheme.primary),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(user?.fullName ?? '-',
                            style: theme.textTheme.titleMedium),
                        const SizedBox(height: 4),
                        Text(user?.phone ?? '-',
                            style: theme.textTheme.bodyMedium),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 24),
          ListTile(
            title: Text(l10n.t('profile.language')),
            trailing: DropdownButton<String>(
              value: currentLocale.languageCode,
              onChanged: (v) =>
                  localeNotifier.setLocale(v == null ? null : Locale(v)),
              items: const [
                DropdownMenuItem(value: 'en', child: Text('English')),
                DropdownMenuItem(value: 'fa', child: Text('فارسی')),
                DropdownMenuItem(value: 'de', child: Text('Deutsch')),
              ],
            ),
          ),
          ListTile(
            title: Text(l10n.t('profile.theme')),
            trailing: DropdownButton<ThemeMode>(
              value: mode,
              onChanged: (v) {
                if (v != null) {
                  ref.read(themeModeProvider.notifier).setMode(v);
                }
              },
              items: [
                DropdownMenuItem(
                  value: ThemeMode.system,
                  child: Text(l10n.t('profile.theme.system')),
                ),
                DropdownMenuItem(
                  value: ThemeMode.light,
                  child: Text(l10n.t('profile.theme.light')),
                ),
                DropdownMenuItem(
                  value: ThemeMode.dark,
                  child: Text(l10n.t('profile.theme.dark')),
                ),
              ],
            ),
          ),
          const Divider(height: 32),
          OutlinedButton.icon(
            icon: const Icon(Icons.logout),
            label: Text(l10n.t('auth.signOut')),
            onPressed: () => ref.read(authProvider.notifier).logout(),
          ),
        ],
      ),
    );
  }
}
