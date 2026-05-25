// ignore_for_file: deprecated_member_use
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/models/order_model.dart';
import '../../../../core/models/slot_model.dart';
import '../../../../core/network/api_exception.dart';
import '../../../scheduling/data/scheduling_repository.dart';
import '../../data/orders_repository.dart';
import 'review_screen.dart';

class UserOrderDetailScreen extends ConsumerWidget {
  const UserOrderDetailScreen({super.key, required this.orderId});

  final int orderId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final orderAsync = ref.watch(orderDetailProvider(orderId));
    final slotsAsync = ref.watch(orderSlotsProvider(orderId));

    return Scaffold(
      appBar: AppBar(title: Text(l10n.t('order.detail'))),
      body: RefreshIndicator(
        onRefresh: () async {
          ref.invalidate(orderDetailProvider(orderId));
          ref.invalidate(orderSlotsProvider(orderId));
          await ref.read(orderDetailProvider(orderId).future);
        },
        child: orderAsync.when(
          loading: () => const Center(child: CircularProgressIndicator()),
          error: (e, _) => _error(context, e),
          data: (order) => ListView(
            padding: const EdgeInsets.all(16),
            children: [
              _StatusCard(order: order),
              const SizedBox(height: 16),
              _DetailsCard(order: order),
              if (order.status == OrderStatus.awaitingUserConfirm) ...[
                const SizedBox(height: 16),
                _SlotPickerSection(orderId: orderId, slotsAsync: slotsAsync),
              ],
              if (order.status == OrderStatus.timeConfirmed ||
                  order.status == OrderStatus.priceConfirmed ||
                  order.status == OrderStatus.inProgress ||
                  order.status == OrderStatus.completed) ...[
                const SizedBox(height: 16),
                _ConfirmedSlotCard(slotsAsync: slotsAsync),
              ],
              if (order.totalPrice != null) ...[
                const SizedBox(height: 16),
                _PriceCard(order: order),
              ],
              if (order.canCancel) ...[
                const SizedBox(height: 24),
                OutlinedButton.icon(
                  onPressed: () => _confirmCancel(context, ref, order),
                  icon: const Icon(Icons.cancel_outlined),
                  label: Text(l10n.t('order.cancel')),
                ),
              ],
              if (order.canReview) ...[
                const SizedBox(height: 24),
                FilledButton.icon(
                  onPressed: () async {
                    await Navigator.of(context).push(
                      MaterialPageRoute(
                        builder: (_) => ReviewScreen(orderId: orderId),
                      ),
                    );
                    if (context.mounted) {
                      ref.invalidate(orderDetailProvider(orderId));
                    }
                  },
                  icon: const Icon(Icons.star_outline),
                  label: Text(l10n.t('order.leaveReview')),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _error(BuildContext context, Object e) {
    final l10n = AppLocalizations.of(context);
    final msg = e is ApiException ? e.message : '$e';
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        const SizedBox(height: 40),
        Icon(Icons.error_outline,
            size: 36, color: Theme.of(context).colorScheme.error),
        const SizedBox(height: 8),
        Text(msg, textAlign: TextAlign.center),
        const SizedBox(height: 8),
        Center(child: Text(l10n.t('common.retry'))),
      ],
    );
  }

  Future<void> _confirmCancel(
    BuildContext context,
    WidgetRef ref,
    OrderModel order,
  ) async {
    final l10n = AppLocalizations.of(context);
    final reasonCtrl = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.t('order.cancelTitle')),
        content: TextField(
          controller: reasonCtrl,
          decoration:
              InputDecoration(labelText: l10n.t('order.cancelReason')),
          maxLength: 500,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: Text(l10n.t('common.no')),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: Text(l10n.t('common.yes')),
          ),
        ],
      ),
    );
    if (ok != true) return;
    try {
      await ref.read(ordersRepositoryProvider).cancelOrder(
            order.id,
            reason: reasonCtrl.text.trim().isEmpty
                ? null
                : reasonCtrl.text.trim(),
          );
      ref.invalidate(orderDetailProvider(order.id));
      ref.invalidate(myOrdersProvider);
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('$e')),
        );
      }
    }
  }
}

class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.order});
  final OrderModel order;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    return Card(
      color: theme.colorScheme.primaryContainer,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            const Icon(Icons.receipt_long_outlined),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('#${order.id}', style: theme.textTheme.titleMedium),
                  const SizedBox(height: 4),
                  Text(l10n.t('orders.status.${order.status}'),
                      style: theme.textTheme.bodyMedium),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _DetailsCard extends StatelessWidget {
  const _DetailsCard({required this.order});
  final OrderModel order;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(l10n.t('order.services'),
                style: theme.textTheme.titleMedium),
            const SizedBox(height: 4),
            Wrap(
              spacing: 6,
              children: order.serviceKeys
                  .map((k) => Chip(label: Text(k)))
                  .toList(),
            ),
            if (order.addressText != null && order.addressText!.isNotEmpty) ...[
              const SizedBox(height: 12),
              Text(l10n.t('order.address'),
                  style: theme.textTheme.titleSmall),
              Text(order.addressText!),
            ],
            if (order.latitude != null && order.longitude != null) ...[
              const SizedBox(height: 4),
              Text(
                '${order.latitude!.toStringAsFixed(5)}, '
                '${order.longitude!.toStringAsFixed(5)}',
                style: theme.textTheme.bodySmall,
              ),
            ],
            if (order.notes != null && order.notes!.isNotEmpty) ...[
              const SizedBox(height: 12),
              Text(l10n.t('order.notes'),
                  style: theme.textTheme.titleSmall),
              Text(order.notes!),
            ],
          ],
        ),
      ),
    );
  }
}

class _PriceCard extends StatelessWidget {
  const _PriceCard({required this.order});
  final OrderModel order;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    return Card(
      child: ListTile(
        leading: const Icon(Icons.payments_outlined),
        title: Text(l10n.t('order.totalPrice')),
        trailing: Text(
          '${order.totalPrice!.toStringAsFixed(2)} €',
          style: theme.textTheme.titleLarge,
        ),
        subtitle: order.execDurationMinutes != null
            ? Text(l10n.t('order.duration', args: {
                'minutes': order.execDurationMinutes!,
              }))
            : null,
      ),
    );
  }
}

class _ConfirmedSlotCard extends StatelessWidget {
  const _ConfirmedSlotCard({required this.slotsAsync});
  final AsyncValue<List<SlotModel>> slotsAsync;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    return slotsAsync.maybeWhen(
      orElse: () => const SizedBox.shrink(),
      data: (list) {
        final confirmed = list.where((s) => s.isConfirmed).toList();
        if (confirmed.isEmpty) return const SizedBox.shrink();
        final s = confirmed.first;
        final df = DateFormat.yMMMMd(
          Localizations.localeOf(context).languageCode,
        ).add_Hm();
        return Card(
          child: ListTile(
            leading: const Icon(Icons.event_available_outlined),
            title: Text(l10n.t('order.confirmedTime')),
            subtitle: Text(df.format(s.startAt)),
            trailing: Text(
              '${s.endAt.difference(s.startAt).inMinutes} min',
              style: theme.textTheme.bodySmall,
            ),
          ),
        );
      },
    );
  }
}

class _SlotPickerSection extends ConsumerStatefulWidget {
  const _SlotPickerSection({required this.orderId, required this.slotsAsync});

  final int orderId;
  final AsyncValue<List<SlotModel>> slotsAsync;

  @override
  ConsumerState<_SlotPickerSection> createState() =>
      _SlotPickerSectionState();
}

class _SlotPickerSectionState extends ConsumerState<_SlotPickerSection> {
  int? _selectedId;
  bool _submitting = false;
  String? _error;

  Future<void> _confirm() async {
    if (_selectedId == null) return;
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      await ref.read(schedulingRepositoryProvider).confirmSlot(
            requestId: widget.orderId,
            slotId: _selectedId!,
          );
      ref.invalidate(orderDetailProvider(widget.orderId));
      ref.invalidate(orderSlotsProvider(widget.orderId));
    } on ApiException catch (e) {
      setState(() => _error = e.message);
    } catch (e) {
      setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _submitting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    final df = DateFormat.yMMMMd(
      Localizations.localeOf(context).languageCode,
    ).add_Hm();

    return widget.slotsAsync.when(
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (e, _) => Text(e is ApiException ? e.message : '$e'),
      data: (list) {
        final proposed = list.where((s) => s.isProposed).toList();
        if (proposed.isEmpty) {
          return Text(l10n.t('order.noProposedSlots'));
        }
        return Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(l10n.t('order.pickAProposedTime'),
                    style: theme.textTheme.titleMedium),
                const SizedBox(height: 8),
                ...proposed.map((s) {
                  return RadioListTile<int>(
                    value: s.id,
                    groupValue: _selectedId,
                    onChanged: (v) => setState(() => _selectedId = v),
                    title: Text(df.format(s.startAt)),
                    subtitle: Text(df.format(s.endAt)),
                  );
                }),
                if (_error != null) ...[
                  const SizedBox(height: 8),
                  Text(_error!,
                      style: TextStyle(color: theme.colorScheme.error)),
                ],
                const SizedBox(height: 8),
                FilledButton.icon(
                  onPressed:
                      _submitting || _selectedId == null ? null : _confirm,
                  icon: _submitting
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.check),
                  label: Text(l10n.t('order.confirmTime')),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}
