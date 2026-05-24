import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/network/api_client.dart';
import '../../../../core/network/api_exception.dart';

final _ordersProvider =
    FutureProvider<List<Map<String, dynamic>>>((ref) async {
  final api = ref.watch(apiClientProvider);
  final data = await api.get<List<dynamic>>('/orders');
  return data.map((e) => Map<String, dynamic>.from(e as Map)).toList();
});

class UserOrdersScreen extends ConsumerWidget {
  const UserOrdersScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    final orders = ref.watch(_ordersProvider);
    return Scaffold(
      appBar: AppBar(title: Text(l10n.t('nav.orderHistory'))),
      body: RefreshIndicator(
        onRefresh: () async => ref.refresh(_ordersProvider.future),
        child: orders.when(
          data: (list) {
            if (list.isEmpty) {
              return ListView(
                children: [
                  const SizedBox(height: 64),
                  Icon(Icons.receipt_long_outlined,
                      size: 56, color: theme.colorScheme.onSurfaceVariant),
                  const SizedBox(height: 8),
                  Center(child: Text(l10n.t('home.noOrders'))),
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
                    leading: const Icon(Icons.cleaning_services_outlined),
                    title: Text('#${o['id']}'),
                    subtitle: Text(l10n.t('orders.status.$status')),
                    trailing: o['total_price'] != null
                        ? Text('${o['total_price']} €')
                        : null,
                  ),
                );
              },
            );
          },
          loading: () => const Center(child: CircularProgressIndicator()),
          error: (e, _) {
            final msg = e is ApiException ? e.message : '$e';
            return Center(child: Text(msg));
          },
        ),
      ),
    );
  }
}
