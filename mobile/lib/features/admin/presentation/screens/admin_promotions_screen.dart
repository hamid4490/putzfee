import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/images/image_picker_helper.dart';
import '../../../../core/localization/app_localizations.dart';
import '../../../../core/models/promotion_model.dart';
import '../../../../core/network/api_exception.dart';
import '../../data/admin_repository.dart';
import '../widgets/i18n_field_editor.dart';

class AdminPromotionsScreen extends ConsumerWidget {
  const AdminPromotionsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final promos = ref.watch(adminPromotionsProvider);
    return Scaffold(
      appBar: AppBar(title: Text(l10n.t('nav.promotions'))),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _showEditor(context, ref),
        icon: const Icon(Icons.add),
        label: Text(l10n.t('admin.addPromotion')),
      ),
      body: promos.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) =>
            Center(child: Text(e is ApiException ? e.message : '$e')),
        data: (list) {
          if (list.isEmpty) return Center(child: Text(l10n.t('common.empty')));
          return RefreshIndicator(
            onRefresh: () async => ref.refresh(adminPromotionsProvider.future),
            child: ListView.builder(
              itemCount: list.length,
              itemBuilder: (context, i) {
                final p = list[i];
                final code = Localizations.localeOf(context).languageCode;
                return Card(
                  margin:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                  child: ListTile(
                    leading: p.imageUrl != null
                        ? Image.network(p.imageUrl!,
                            width: 50,
                            height: 50,
                            fit: BoxFit.cover,
                            errorBuilder: (_, __, ___) =>
                                const Icon(Icons.image_not_supported))
                        : const Icon(Icons.local_offer_outlined),
                    title: Text(p.titleFor(code)),
                    subtitle: Text(_subtitle(p)),
                    trailing: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        IconButton(
                          icon: const Icon(Icons.upload_outlined),
                          onPressed: () => _uploadImage(context, ref, p),
                        ),
                        IconButton(
                          icon: const Icon(Icons.edit_outlined),
                          onPressed: () =>
                              _showEditor(context, ref, existing: p),
                        ),
                        IconButton(
                          icon: const Icon(Icons.delete_outline),
                          onPressed: () => _confirmDelete(context, ref, p),
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

  String _subtitle(PromotionModel p) {
    final parts = <String>[];
    parts.add(p.key);
    if (p.discountPercent != null) parts.add('-${p.discountPercent}%');
    if (p.flatDiscount != null) parts.add('-${p.flatDiscount} €');
    parts.add(p.isActive ? 'active' : 'inactive');
    return parts.join(' · ');
  }

  Future<void> _uploadImage(
      BuildContext context, WidgetRef ref, PromotionModel p) async {
    final File? file = await pickAndCompressImage();
    if (file == null) return;
    try {
      await ref.read(adminRepositoryProvider).uploadPromotionImage(p.id, file);
      ref.invalidate(adminPromotionsProvider);
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('$e')));
      }
    }
  }

  Future<void> _confirmDelete(
      BuildContext context, WidgetRef ref, PromotionModel p) async {
    final l10n = AppLocalizations.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.t('admin.deletePromotion')),
        content: Text(p.key),
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
      await ref.read(adminRepositoryProvider).deletePromotion(p.id);
      ref.invalidate(adminPromotionsProvider);
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('$e')));
      }
    }
  }

  Future<void> _showEditor(BuildContext context, WidgetRef ref,
      {PromotionModel? existing}) async {
    await showDialog<void>(
      context: context,
      builder: (_) => _PromotionEditor(existing: existing),
    );
  }
}

class _PromotionEditor extends ConsumerStatefulWidget {
  const _PromotionEditor({this.existing});
  final PromotionModel? existing;

  @override
  ConsumerState<_PromotionEditor> createState() => _PromotionEditorState();
}

class _PromotionEditorState extends ConsumerState<_PromotionEditor> {
  late TextEditingController _keyCtrl;
  late TextEditingController _percentCtrl;
  late TextEditingController _flatCtrl;
  late TextEditingController _minServicesCtrl;
  late Map<String, TextEditingController> _titles;
  late Map<String, TextEditingController> _descs;
  late bool _isActive;
  bool _submitting = false;
  String? _error;

  static const _locales = ['en', 'fa', 'de'];

  @override
  void initState() {
    super.initState();
    final e = widget.existing;
    _keyCtrl = TextEditingController(text: e?.key ?? '');
    _percentCtrl =
        TextEditingController(text: e?.discountPercent?.toString() ?? '');
    _flatCtrl = TextEditingController(text: e?.flatDiscount?.toString() ?? '');
    _minServicesCtrl =
        TextEditingController(text: e?.minServices?.toString() ?? '');
    _titles = {
      for (final l in _locales)
        l: TextEditingController(text: e?.titleI18n[l] ?? '')
    };
    _descs = {
      for (final l in _locales)
        l: TextEditingController(text: e?.descriptionI18n[l] ?? '')
    };
    _isActive = e?.isActive ?? true;
  }

  @override
  void dispose() {
    _keyCtrl.dispose();
    _percentCtrl.dispose();
    _flatCtrl.dispose();
    _minServicesCtrl.dispose();
    for (final c in _titles.values) {
      c.dispose();
    }
    for (final c in _descs.values) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> _save() async {
    if (_keyCtrl.text.trim().isEmpty) {
      setState(() => _error = 'key required');
      return;
    }
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final model = PromotionModel(
        id: widget.existing?.id ?? 0,
        key: _keyCtrl.text.trim(),
        titleI18n: {
          for (final entry in _titles.entries)
            if (entry.value.text.trim().isNotEmpty)
              entry.key: entry.value.text.trim()
        },
        descriptionI18n: {
          for (final entry in _descs.entries)
            if (entry.value.text.trim().isNotEmpty)
              entry.key: entry.value.text.trim()
        },
        imageUrl: widget.existing?.imageUrl,
        discountPercent: double.tryParse(_percentCtrl.text.trim()),
        flatDiscount: double.tryParse(_flatCtrl.text.trim()),
        minServices: int.tryParse(_minServicesCtrl.text.trim()),
        appliesToKeys: widget.existing?.appliesToKeys,
        validFrom: widget.existing?.validFrom,
        validTo: widget.existing?.validTo,
        isActive: _isActive,
      );
      await ref.read(adminRepositoryProvider).upsertPromotion(model);
      ref.invalidate(adminPromotionsProvider);
      if (mounted) Navigator.of(context).pop();
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
    return AlertDialog(
      title: Text(widget.existing == null
          ? l10n.t('admin.addPromotion')
          : l10n.t('admin.editPromotion')),
      content: SizedBox(
        width: 480,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: _keyCtrl,
                decoration: InputDecoration(
                    labelText: l10n.t('admin.promotionKey')),
                enabled: widget.existing == null,
              ),
              I18nFieldEditor(
                title: l10n.t('admin.promotionTitle'),
                controllers: _titles,
              ),
              I18nFieldEditor(
                title: l10n.t('admin.promotionDescription'),
                controllers: _descs,
                multiline: true,
              ),
              TextField(
                controller: _percentCtrl,
                keyboardType:
                    const TextInputType.numberWithOptions(decimal: true),
                decoration: InputDecoration(
                  labelText: l10n.t('admin.discountPercent'),
                  suffixText: '%',
                ),
              ),
              TextField(
                controller: _flatCtrl,
                keyboardType:
                    const TextInputType.numberWithOptions(decimal: true),
                decoration: InputDecoration(
                  labelText: l10n.t('admin.flatDiscount'),
                  suffixText: '€',
                ),
              ),
              TextField(
                controller: _minServicesCtrl,
                keyboardType: TextInputType.number,
                decoration: InputDecoration(
                    labelText: l10n.t('admin.minServices')),
              ),
              SwitchListTile(
                value: _isActive,
                onChanged: (v) => setState(() => _isActive = v),
                title: Text(l10n.t('admin.isActive')),
              ),
              if (_error != null) ...[
                const SizedBox(height: 8),
                Text(_error!,
                    style:
                        TextStyle(color: Theme.of(context).colorScheme.error)),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(l10n.t('common.cancel')),
        ),
        FilledButton(
          onPressed: _submitting ? null : _save,
          child: Text(l10n.t('common.save')),
        ),
      ],
    );
  }
}
