import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/models/order_model.dart';
import '../../../../core/network/api_exception.dart';
import '../../data/admin_repository.dart';

class AdminOrdersScreen extends ConsumerWidget {
  const AdminOrdersScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    return DefaultTabController(
      length: 2,
      child: Scaffold(
        appBar: AppBar(
          title: Text(l10n.t('admin.orders')),
          bottom: TabBar(
            tabs: [
              Tab(text: l10n.t('admin.activeOrders')),
              Tab(text: l10n.t('admin.history')),
            ],
          ),
        ),
        body: const TabBarView(
          children: [
            _OrdersList(history: false),
            _OrdersList(history: true),
          ],
        ),
      ),
    );
  }
}

class _OrdersList extends ConsumerWidget {
  const _OrdersList({required this.history});
  final bool history;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    final code = Localizations.localeOf(context).languageCode;
    final df = DateFormat.yMMMd(code).add_Hm();
    final asyncPage = history
        ? ref.watch(adminHistoryProvider)
        : ref.watch(adminActiveOrdersProvider);
    return RefreshIndicator(
      onRefresh: () async {
        if (history) {
          ref.invalidate(adminHistoryProvider);
          await ref.read(adminHistoryProvider.future);
        } else {
          ref.invalidate(adminActiveOrdersProvider);
          await ref.read(adminActiveOrdersProvider.future);
        }
      },
      child: asyncPage.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) {
          final msg = e is ApiException ? e.message : '$e';
          return ListView(
            children: [
              const SizedBox(height: 40),
              Center(child: Text(msg)),
            ],
          );
        },
        data: (page) {
          if (page.items.isEmpty) {
            return ListView(
              children: [
                const SizedBox(height: 64),
                Center(child: Text(l10n.t('common.empty'))),
              ],
            );
          }
          return ListView.separated(
            padding: const EdgeInsets.all(16),
            itemCount: page.items.length,
            separatorBuilder: (_, __) => const SizedBox(height: 8),
            itemBuilder: (context, i) {
              final OrderModel o = page.items[i];
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
                  onTap: () => context.push('/admin/orders/${o.id}'),
                ),
              );
            },
          );
        },
      ),
    );
  }
}
