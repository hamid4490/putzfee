import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/network/api_exception.dart';
import '../../data/orders_repository.dart';

class UserOrdersScreen extends ConsumerWidget {
  const UserOrdersScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    final orders = ref.watch(myOrdersProvider);
    final code = Localizations.localeOf(context).languageCode;
    final df = DateFormat.yMMMd(code).add_Hm();

    return Scaffold(
      appBar: AppBar(title: Text(l10n.t('nav.orderHistory'))),
      body: RefreshIndicator(
        onRefresh: () async => ref.refresh(myOrdersProvider.future),
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
                return Card(
                  child: ListTile(
                    leading: const Icon(Icons.cleaning_services_outlined),
                    title: Text('#${o.id} – ${o.serviceKeys.join(', ')}'),
                    subtitle: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(l10n.t('orders.status.${o.status}')),
                        Text(df.format(o.createdAt),
                            style: theme.textTheme.bodySmall),
                      ],
                    ),
                    trailing: o.totalPrice != null
                        ? Text('${o.totalPrice!.toStringAsFixed(2)} €',
                            style: theme.textTheme.titleSmall)
                        : const Icon(Icons.chevron_right),
                    onTap: () => context.push('/orders/${o.id}'),
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
