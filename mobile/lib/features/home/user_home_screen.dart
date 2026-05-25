import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/localization/app_localizations.dart';
import '../../core/network/api_client.dart';
import '../../core/network/api_exception.dart';
import '../auth/presentation/providers/auth_provider.dart';

class _HomePayload {
  _HomePayload({required this.services, required this.promotions});
  final List<Map<String, dynamic>> services;
  final List<Map<String, dynamic>> promotions;
}

final _publicHomeProvider = FutureProvider<_HomePayload>((ref) async {
  final api = ref.watch(apiClientProvider);
  final data = await api.get<Map<String, dynamic>>('/public/home');
  return _HomePayload(
    services: (data['services'] as List? ?? const [])
        .map((e) => Map<String, dynamic>.from(e as Map))
        .toList(),
    promotions: (data['promotions'] as List? ?? const [])
        .map((e) => Map<String, dynamic>.from(e as Map))
        .toList(),
  );
});

class UserHomeScreen extends ConsumerWidget {
  const UserHomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    final user = ref.watch(authProvider).user;
    final home = ref.watch(_publicHomeProvider);
    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.t('app_title')),
        actions: [
          IconButton(
            icon: const Icon(Icons.directions_car_outlined),
            tooltip: l10n.t('cars.title'),
            onPressed: () => context.push('/cars'),
          ),
          IconButton(
            icon: const Icon(Icons.notifications_none),
            tooltip: l10n.t('notifications.title'),
            onPressed: () => context.push('/notifications'),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: () async => ref.refresh(_publicHomeProvider.future),
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Text(
              l10n.t('home.hello',
                  args: {'name': user?.fullName ?? ''}).trim(),
              style: theme.textTheme.headlineSmall,
            ),
            const SizedBox(height: 8),
            Text(l10n.t('tagline'), style: theme.textTheme.bodyMedium),
            const SizedBox(height: 16),
            Card(
              child: ListTile(
                leading: const Icon(Icons.add_box_outlined),
                title: Text(l10n.t('home.bookNow')),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => context.push('/orders/new'),
              ),
            ),
            const SizedBox(height: 24),
            home.when(
              data: (payload) => _HomeContent(payload: payload, l10n: l10n),
              loading: () => const Center(
                child: Padding(
                  padding: EdgeInsets.symmetric(vertical: 48),
                  child: CircularProgressIndicator(),
                ),
              ),
              error: (e, _) {
                final msg = e is ApiException ? e.message : '$e';
                return Padding(
                  padding: const EdgeInsets.symmetric(vertical: 32),
                  child: Column(
                    children: [
                      Icon(Icons.error_outline,
                          color: theme.colorScheme.error, size: 32),
                      const SizedBox(height: 8),
                      Text(msg, textAlign: TextAlign.center),
                      const SizedBox(height: 8),
                      OutlinedButton(
                        onPressed: () => ref.refresh(_publicHomeProvider),
                        child: Text(l10n.t('common.retry')),
                      ),
                    ],
                  ),
                );
              },
            ),
          ],
        ),
      ),
    );
  }
}

class _HomeContent extends StatelessWidget {
  const _HomeContent({required this.payload, required this.l10n});

  final _HomePayload payload;
  final AppLocalizations l10n;

  String _name(Map<String, dynamic> i18n, String code) {
    final v = i18n[code] ?? i18n['en'] ?? i18n.values.cast<dynamic>().firstOrNull;
    return v?.toString() ?? '';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final code = Localizations.localeOf(context).languageCode;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (payload.promotions.isNotEmpty) ...[
          Text(l10n.t('home.activePromotions'),
              style: theme.textTheme.titleMedium),
          const SizedBox(height: 8),
          SizedBox(
            height: 120,
            child: ListView.separated(
              scrollDirection: Axis.horizontal,
              itemCount: payload.promotions.length,
              separatorBuilder: (_, __) => const SizedBox(width: 12),
              itemBuilder: (context, i) {
                final p = payload.promotions[i];
                final title = _name(
                    Map<String, dynamic>.from(p['title_i18n'] as Map? ?? {}),
                    code);
                return SizedBox(
                  width: 240,
                  child: Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(title,
                              style: theme.textTheme.titleSmall,
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis),
                          const Spacer(),
                          if (p['discount_percent'] != null)
                            Text('-${p['discount_percent']}%',
                                style: theme.textTheme.headlineSmall
                                    ?.copyWith(color: theme.colorScheme.primary)),
                        ],
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
          const SizedBox(height: 24),
        ],
        Text(l10n.t('home.popularServices'),
            style: theme.textTheme.titleMedium),
        const SizedBox(height: 8),
        ...payload.services.map((s) {
          final title = _name(
              Map<String, dynamic>.from(s['name_i18n'] as Map? ?? {}), code);
          return Card(
            child: ListTile(
              leading: const Icon(Icons.cleaning_services_outlined),
              title: Text(title),
              subtitle:
                  s['base_price'] != null ? Text('${s['base_price']} €') : null,
              trailing: const Icon(Icons.chevron_right),
              onTap: () {
                // TODO: navigate to service detail / order flow.
              },
            ),
          );
        }),
      ],
    );
  }
}

extension<E> on Iterable<E> {
  E? get firstOrNull => isEmpty ? null : first;
}
