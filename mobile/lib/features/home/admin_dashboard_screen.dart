import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/localization/app_localizations.dart';
import '../../core/network/api_client.dart';
import '../../core/network/api_exception.dart';

final _pendingOrdersProvider =
    FutureProvider<List<Map<String, dynamic>>>((ref) async {
  final api = ref.watch(apiClientProvider);
  final data = await api.get<List<dynamic>>(
    '/admin/orders',
    query: {'limit': 20},
  );
  return data.map((e) => Map<String, dynamic>.from(e as Map)).toList();
});

class AdminDashboardScreen extends ConsumerWidget {
  const AdminDashboardScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    final orders = ref.watch(_pendingOrdersProvider);
    return Scaffold(
      appBar: AppBar(title: Text(l10n.t('nav.dashboard'))),
      body: RefreshIndicator(
        onRefresh: () async => ref.refresh(_pendingOrdersProvider.future),
        child: orders.when(
          data: (list) {
            if (list.isEmpty) {
              return ListView(
                children: [
                  const SizedBox(height: 64),
                  Icon(Icons.inbox_outlined,
                      size: 56, color: theme.colorScheme.onSurfaceVariant),
                  const SizedBox(height: 8),
                  Center(child: Text(l10n.t('common.empty'))),
                ],
              );
            }
            return ListView.separated(
              padding: const EdgeInsets.all(16),
              itemCount: list.length,
              separatorBuilder: (_, __) => const SizedBox(height: 8),
              itemBuilder: (context, i) {
                final o = list[i];
                final status = o['status']?.toString() ?? '';
                return Card(
                  child: ListTile(
                    title: Text('#${o['id']} • ${o['address_text'] ?? '—'}'),
                    subtitle: Text(
                      l10n.t('orders.status.$status'),
                      style: TextStyle(color: theme.colorScheme.primary),
                    ),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () {
                      // TODO: navigate to admin order detail.
                    },
                  ),
                );
              },
            );
          },
          loading: () =>
              const Center(child: CircularProgressIndicator()),
          error: (e, _) {
            final msg = e is ApiException ? e.message : '$e';
            return Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.error_outline,
                      color: theme.colorScheme.error, size: 40),
                  const SizedBox(height: 8),
                  Text(msg),
                  const SizedBox(height: 8),
                  OutlinedButton(
                    onPressed: () => ref.refresh(_pendingOrdersProvider),
                    child: Text(l10n.t('common.retry')),
                  ),
                ],
              ),
            );
          },
        ),
      ),
    );
  }
}
