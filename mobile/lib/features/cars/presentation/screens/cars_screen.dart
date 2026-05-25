import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/models/car_model.dart';
import '../../../../core/network/api_exception.dart';
import '../../data/cars_repository.dart';

class CarsScreen extends ConsumerWidget {
  const CarsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final cars = ref.watch(carsProvider);
    return Scaffold(
      appBar: AppBar(title: Text(l10n.t('cars.title'))),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _showEditor(context, ref),
        icon: const Icon(Icons.add),
        label: Text(l10n.t('cars.add')),
      ),
      body: cars.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) {
          final msg = e is ApiException ? e.message : '$e';
          return Center(child: Text(msg));
        },
        data: (list) {
          if (list.isEmpty) {
            return Center(child: Text(l10n.t('cars.empty')));
          }
          return RefreshIndicator(
            onRefresh: () async => ref.refresh(carsProvider.future),
            child: ListView.builder(
              itemCount: list.length,
              itemBuilder: (context, i) {
                final c = list[i];
                return Card(
                  margin:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                  child: ListTile(
                    leading: const Icon(Icons.directions_car_outlined),
                    title: Text(c.displayName),
                    subtitle: c.color != null && c.color!.isNotEmpty
                        ? Text(c.color!)
                        : null,
                    trailing: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        IconButton(
                          icon: const Icon(Icons.edit_outlined),
                          onPressed: () => _showEditor(context, ref, car: c),
                        ),
                        IconButton(
                          icon: const Icon(Icons.delete_outline),
                          onPressed: () => _confirmDelete(context, ref, c),
                        ),
                      ],
                    ),
                  ),
                );
              },
            ),
          );
        },
      ),
    );
  }

  Future<void> _showEditor(
    BuildContext context,
    WidgetRef ref, {
    CarModel? car,
  }) async {
    final l10n = AppLocalizations.of(context);
    final brandCtrl = TextEditingController(text: car?.brand ?? '');
    final modelCtrl = TextEditingController(text: car?.model ?? '');
    final plateCtrl = TextEditingController(text: car?.plate ?? '');
    final colorCtrl = TextEditingController(text: car?.color ?? '');
    final formKey = GlobalKey<FormState>();

    await showDialog<void>(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: Text(car == null ? l10n.t('cars.add') : l10n.t('cars.edit')),
          content: Form(
            key: formKey,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextFormField(
                  controller: brandCtrl,
                  decoration: InputDecoration(labelText: l10n.t('cars.brand')),
                  validator: (v) =>
                      (v == null || v.trim().isEmpty) ? l10n.t('common.required') : null,
                ),
                TextFormField(
                  controller: modelCtrl,
                  decoration: InputDecoration(labelText: l10n.t('cars.model')),
                  validator: (v) =>
                      (v == null || v.trim().isEmpty) ? l10n.t('common.required') : null,
                ),
                TextFormField(
                  controller: plateCtrl,
                  decoration: InputDecoration(labelText: l10n.t('cars.plate')),
                ),
                TextFormField(
                  controller: colorCtrl,
                  decoration: InputDecoration(labelText: l10n.t('cars.color')),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: Text(l10n.t('common.cancel')),
            ),
            FilledButton(
              onPressed: () async {
                if (!formKey.currentState!.validate()) return;
                final repo = ref.read(carsRepositoryProvider);
                try {
                  if (car == null) {
                    await repo.create(
                      brand: brandCtrl.text.trim(),
                      model: modelCtrl.text.trim(),
                      plate: plateCtrl.text.trim().isEmpty
                          ? null
                          : plateCtrl.text.trim(),
                      color: colorCtrl.text.trim().isEmpty
                          ? null
                          : colorCtrl.text.trim(),
                    );
                  } else {
                    await repo.update(
                      id: car.id,
                      brand: brandCtrl.text.trim(),
                      model: modelCtrl.text.trim(),
                      plate: plateCtrl.text.trim().isEmpty
                          ? null
                          : plateCtrl.text.trim(),
                      color: colorCtrl.text.trim().isEmpty
                          ? null
                          : colorCtrl.text.trim(),
                    );
                  }
                  ref.invalidate(carsProvider);
                  if (ctx.mounted) Navigator.of(ctx).pop();
                } catch (e) {
                  if (ctx.mounted) {
                    ScaffoldMessenger.of(ctx).showSnackBar(
                      SnackBar(content: Text('$e')),
                    );
                  }
                }
              },
              child: Text(l10n.t('common.save')),
            ),
          ],
        );
      },
    );
  }

  Future<void> _confirmDelete(
    BuildContext context,
    WidgetRef ref,
    CarModel car,
  ) async {
    final l10n = AppLocalizations.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.t('cars.confirmDelete')),
        content: Text(car.displayName),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: Text(l10n.t('common.cancel')),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: Text(l10n.t('common.delete')),
          ),
        ],
      ),
    );
    if (ok != true) return;
    try {
      await ref.read(carsRepositoryProvider).delete(car.id);
      ref.invalidate(carsProvider);
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('$e')),
        );
      }
    }
  }
}
