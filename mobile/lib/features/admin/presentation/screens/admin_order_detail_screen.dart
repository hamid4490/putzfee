import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/models/order_model.dart';
import '../../../../core/models/slot_model.dart';
import '../../../../core/network/api_exception.dart';
import '../../../orders/data/orders_repository.dart';
import '../../../scheduling/data/scheduling_repository.dart';
import '../../data/admin_repository.dart';

class AdminOrderDetailScreen extends ConsumerWidget {
  const AdminOrderDetailScreen({super.key, required this.orderId});

  final int orderId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final orderAsync = ref.watch(adminOrderDetailProvider(orderId));
    final slotsAsync = ref.watch(orderSlotsProvider(orderId));
    return Scaffold(
      appBar: AppBar(title: Text('${l10n.t('order.detail')} #$orderId')),
      body: RefreshIndicator(
        onRefresh: () async {
          ref.invalidate(adminOrderDetailProvider(orderId));
          ref.invalidate(orderSlotsProvider(orderId));
          await ref.read(adminOrderDetailProvider(orderId).future);
        },
        child: orderAsync.when(
          loading: () => const Center(child: CircularProgressIndicator()),
          error: (e, _) {
            final msg = e is ApiException ? e.message : '$e';
            return ListView(
              children: [const SizedBox(height: 40), Center(child: Text(msg))],
            );
          },
          data: (order) => ListView(
            padding: const EdgeInsets.all(16),
            children: [
              _OrderHeader(order: order),
              const SizedBox(height: 12),
              _DetailsCard(order: order),
              const SizedBox(height: 12),
              _SlotsSection(order: order, slotsAsync: slotsAsync),
              const SizedBox(height: 12),
              if (order.status == OrderStatus.timeConfirmed)
                _PriceSetterCard(orderId: orderId),
              if (order.totalPrice != null) ...[
                const SizedBox(height: 12),
                _CurrentPriceCard(order: order),
              ],
              const SizedBox(height: 24),
              _ActionButtons(order: order),
            ],
          ),
        ),
      ),
    );
  }
}

class _OrderHeader extends StatelessWidget {
  const _OrderHeader({required this.order});
  final OrderModel order;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    return Card(
      color: theme.colorScheme.primaryContainer,
      child: ListTile(
        leading: const Icon(Icons.receipt_long_outlined),
        title: Text('#${order.id}'),
        subtitle: Text(l10n.t('orders.status.${order.status}')),
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
            Wrap(
              spacing: 6,
              children:
                  order.serviceKeys.map((k) => Chip(label: Text(k))).toList(),
            ),
            if (order.addressText != null && order.addressText!.isNotEmpty) ...[
              const SizedBox(height: 8),
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
              const SizedBox(height: 8),
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

class _CurrentPriceCard extends StatelessWidget {
  const _CurrentPriceCard({required this.order});
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

class _SlotsSection extends ConsumerStatefulWidget {
  const _SlotsSection({required this.order, required this.slotsAsync});
  final OrderModel order;
  final AsyncValue<List<SlotModel>> slotsAsync;

  @override
  ConsumerState<_SlotsSection> createState() => _SlotsSectionState();
}

class _SlotsSectionState extends ConsumerState<_SlotsSection> {
  final _picked = <DateTime>[];
  bool _submitting = false;
  String? _error;

  Future<void> _addSlot() async {
    final picked = await showDatePicker(
      context: context,
      firstDate: DateTime.now(),
      lastDate: DateTime.now().add(const Duration(days: 60)),
      initialDate: DateTime.now().add(const Duration(days: 1)),
    );
    if (picked == null || !mounted) return;
    final time = await showTimePicker(
      context: context,
      initialTime: const TimeOfDay(hour: 9, minute: 0),
    );
    if (time == null) return;
    final dt = DateTime(
        picked.year, picked.month, picked.day, time.hour, time.minute);
    setState(() => _picked.add(dt));
  }

  Future<void> _propose() async {
    if (_picked.isEmpty) return;
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      await ref.read(schedulingRepositoryProvider).proposeSlots(
            requestId: widget.order.id,
            slots: _picked,
          );
      _picked.clear();
      ref.invalidate(adminOrderDetailProvider(widget.order.id));
      ref.invalidate(orderSlotsProvider(widget.order.id));
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
    final code = Localizations.localeOf(context).languageCode;
    final df = DateFormat.yMMMd(code).add_Hm();
    final canPropose = widget.order.status == OrderStatus.pendingReview ||
        widget.order.status == OrderStatus.awaitingUserConfirm;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(l10n.t('admin.slots'),
                style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            widget.slotsAsync.when(
              loading: () => const Center(child: CircularProgressIndicator()),
              error: (e, _) => Text(e is ApiException ? e.message : '$e'),
              data: (slots) {
                if (slots.isEmpty) {
                  return Text(l10n.t('admin.noSlotsProposed'));
                }
                return Column(
                  children: slots.map((s) {
                    return ListTile(
                      leading: _slotIcon(s.status),
                      title: Text(df.format(s.startAt)),
                      subtitle: Text('→ ${df.format(s.endAt)} · ${s.status}'),
                      dense: true,
                    );
                  }).toList(),
                );
              },
            ),
            if (canPropose) ...[
              const Divider(height: 24),
              Text(l10n.t('admin.proposeNewSlots'),
                  style: theme.textTheme.titleSmall),
              const SizedBox(height: 8),
              ..._picked.map((d) => ListTile(
                    dense: true,
                    leading: const Icon(Icons.schedule_outlined),
                    title: Text(df.format(d)),
                    trailing: IconButton(
                      icon: const Icon(Icons.close),
                      onPressed: () => setState(() => _picked.remove(d)),
                    ),
                  )),
              Row(
                children: [
                  OutlinedButton.icon(
                    onPressed: _picked.length >= 2 ? null : _addSlot,
                    icon: const Icon(Icons.add),
                    label: Text(l10n.t('admin.addSlot')),
                  ),
                  const SizedBox(width: 8),
                  FilledButton.icon(
                    onPressed:
                        _submitting || _picked.isEmpty ? null : _propose,
                    icon: _submitting
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.send),
                    label: Text(l10n.t('admin.propose')),
                  ),
                ],
              ),
              if (_error != null) ...[
                const SizedBox(height: 8),
                Text(_error!,
                    style: TextStyle(color: theme.colorScheme.error)),
              ],
            ],
          ],
        ),
      ),
    );
  }

  Widget _slotIcon(String status) {
    switch (status) {
      case 'CONFIRMED':
        return const Icon(Icons.check_circle_outline, color: Colors.green);
      case 'REJECTED':
        return const Icon(Icons.cancel_outlined, color: Colors.grey);
      default:
        return const Icon(Icons.schedule_outlined);
    }
  }
}

class _PriceSetterCard extends ConsumerStatefulWidget {
  const _PriceSetterCard({required this.orderId});
  final int orderId;

  @override
  ConsumerState<_PriceSetterCard> createState() => _PriceSetterCardState();
}

class _PriceSetterCardState extends ConsumerState<_PriceSetterCard> {
  final _priceCtrl = TextEditingController();
  final _durationCtrl = TextEditingController(text: '60');
  bool _submitting = false;
  String? _error;

  @override
  void dispose() {
    _priceCtrl.dispose();
    _durationCtrl.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final price = double.tryParse(_priceCtrl.text.trim());
    final dur = int.tryParse(_durationCtrl.text.trim());
    if (price == null || price < 0 || dur == null || dur < 1) {
      setState(() => _error = 'invalid input');
      return;
    }
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      await ref.read(adminRepositoryProvider).setPrice(
            orderId: widget.orderId,
            totalPrice: price,
            execDurationMinutes: dur,
          );
      ref.invalidate(adminOrderDetailProvider(widget.orderId));
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
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(l10n.t('admin.setPrice'),
                style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            TextField(
              controller: _priceCtrl,
              keyboardType: const TextInputType.numberWithOptions(decimal: true),
              decoration: InputDecoration(
                labelText: l10n.t('admin.totalPrice'),
                suffixText: '€',
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _durationCtrl,
              keyboardType: TextInputType.number,
              decoration: InputDecoration(
                labelText: l10n.t('admin.durationMinutes'),
              ),
            ),
            if (_error != null) ...[
              const SizedBox(height: 8),
              Text(_error!,
                  style: TextStyle(color: theme.colorScheme.error)),
            ],
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: _submitting ? null : _submit,
              icon: _submitting
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.check),
              label: Text(l10n.t('common.save')),
            ),
          ],
        ),
      ),
    );
  }
}

class _ActionButtons extends ConsumerWidget {
  const _ActionButtons({required this.order});
  final OrderModel order;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final children = <Widget>[];

    if (order.status == OrderStatus.priceConfirmed) {
      children.add(
        FilledButton.icon(
          onPressed: () => _run(context, ref, (r) => r.startOrder(order.id)),
          icon: const Icon(Icons.play_arrow_outlined),
          label: Text(l10n.t('admin.startWork')),
        ),
      );
    }
    if (order.status == OrderStatus.inProgress) {
      children.add(
        FilledButton.icon(
          onPressed: () =>
              _run(context, ref, (r) => r.finishOrder(order.id)),
          icon: const Icon(Icons.check_circle_outline),
          label: Text(l10n.t('admin.finishWork')),
        ),
      );
    }
    if (!order.isTerminal) {
      children.add(
        OutlinedButton.icon(
          onPressed: () => _cancel(context, ref),
          icon: const Icon(Icons.cancel_outlined),
          label: Text(l10n.t('order.cancel')),
        ),
      );
    }

    if (children.isEmpty) return const SizedBox.shrink();
    return Wrap(spacing: 8, runSpacing: 8, children: children);
  }

  Future<void> _run<T>(
    BuildContext context,
    WidgetRef ref,
    Future<T> Function(AdminRepository) op,
  ) async {
    try {
      await op(ref.read(adminRepositoryProvider));
      ref.invalidate(adminOrderDetailProvider(order.id));
      ref.invalidate(adminActiveOrdersProvider);
    } on ApiException catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.message)),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('$e')),
        );
      }
    }
  }

  Future<void> _cancel(BuildContext context, WidgetRef ref) async {
    final l10n = AppLocalizations.of(context);
    final reasonCtrl = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.t('order.cancelTitle')),
        content: TextField(
          controller: reasonCtrl,
          decoration: InputDecoration(labelText: l10n.t('order.cancelReason')),
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
    if (!context.mounted) return;
    await _run(
      context,
      ref,
      (r) => r.cancelOrder(order.id,
          reason:
              reasonCtrl.text.trim().isEmpty ? null : reasonCtrl.text.trim()),
    );
  }
}
