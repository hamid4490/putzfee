import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/network/api_exception.dart';
import '../../data/notifications_repository.dart';

class NotificationsScreen extends ConsumerWidget {
  const NotificationsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    final asyncList = ref.watch(notificationsProvider);
    final code = Localizations.localeOf(context).languageCode;
    final df = DateFormat.yMMMd(code).add_Hm();
    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.t('notifications.title')),
        actions: [
          IconButton(
            tooltip: l10n.t('notifications.markAllRead'),
            icon: const Icon(Icons.done_all),
            onPressed: () async {
              try {
                await ref.read(notificationsRepositoryProvider).markAllRead();
                ref.invalidate(notificationsProvider);
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context)
                      .showSnackBar(SnackBar(content: Text('$e')));
                }
              }
            },
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: () async => ref.refresh(notificationsProvider.future),
        child: asyncList.when(
          loading: () => const Center(child: CircularProgressIndicator()),
          error: (e, _) {
            final msg = e is ApiException ? e.message : '$e';
            return ListView(
              children: [const SizedBox(height: 40), Center(child: Text(msg))],
            );
          },
          data: (list) {
            if (list.isEmpty) {
              return ListView(
                children: [
                  const SizedBox(height: 64),
                  Icon(Icons.notifications_none,
                      size: 56, color: theme.colorScheme.onSurfaceVariant),
                  const SizedBox(height: 8),
                  Center(child: Text(l10n.t('notifications.empty'))),
                ],
              );
            }
            return ListView.separated(
              padding: const EdgeInsets.all(12),
              itemCount: list.length,
              separatorBuilder: (_, __) => const SizedBox(height: 6),
              itemBuilder: (context, i) {
                final n = list[i];
                final requestId = n.payload?['request_id'];
                return Card(
                  child: ListTile(
                    leading: Icon(
                      n.isUnread
                          ? Icons.notifications_active
                          : Icons.notifications_none,
                      color: n.isUnread ? theme.colorScheme.primary : null,
                    ),
                    title: Text(n.title),
                    subtitle: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        if (n.body != null) Text(n.body!),
                        Text(df.format(n.createdAt),
                            style: theme.textTheme.bodySmall),
                      ],
                    ),
                    onTap: () async {
                      if (n.isUnread) {
                        try {
                          await ref
                              .read(notificationsRepositoryProvider)
                              .markRead(n.id);
                          ref.invalidate(notificationsProvider);
                        } catch (_) {}
                      }
                      if (requestId is num && context.mounted) {
                        context.push('/orders/${requestId.toInt()}');
                      }
                    },
                  ),
                );
              },
            );
          },
        ),
      ),
    );
  }
}
