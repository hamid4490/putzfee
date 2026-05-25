import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/images/image_picker_helper.dart';
import '../../../../core/localization/app_localizations.dart';
import '../../../../core/models/service_model.dart';
import '../../../../core/network/api_exception.dart';
import '../../data/admin_repository.dart';
import '../widgets/i18n_field_editor.dart';

class AdminServicesScreen extends ConsumerWidget {
  const AdminServicesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final services = ref.watch(adminServicesProvider);
    return Scaffold(
      appBar: AppBar(title: Text(l10n.t('nav.services'))),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _showEditor(context, ref),
        icon: const Icon(Icons.add),
        label: Text(l10n.t('admin.addService')),
      ),
      body: services.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) => Center(
          child: Text(e is ApiException ? e.message : '$e'),
        ),
        data: (list) {
          if (list.isEmpty) return Center(child: Text(l10n.t('common.empty')));
          return RefreshIndicator(
            onRefresh: () async => ref.refresh(adminServicesProvider.future),
            child: ListView.builder(
              itemCount: list.length,
              itemBuilder: (context, i) {
                final s = list[i];
                final code = Localizations.localeOf(context).languageCode;
                return Card(
                  margin:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                  child: ListTile(
                    leading: s.icon != null
                        ? Image.network(s.icon!,
                            width: 40,
                            height: 40,
                            errorBuilder: (_, __, ___) =>
                                const Icon(Icons.image_not_supported))
                        : const Icon(Icons.cleaning_services_outlined),
                    title: Text(s.nameFor(code)),
                    subtitle: Text('${s.key} · '
                        '${s.basePrice.toStringAsFixed(2)} € · '
                        '${s.isActive ? "active" : "inactive"}'),
                    trailing: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        IconButton(
                          icon: const Icon(Icons.upload_outlined),
                          onPressed: () => _uploadIcon(context, ref, s),
                        ),
                        IconButton(
                          icon: const Icon(Icons.edit_outlined),
                          onPressed: () =>
                              _showEditor(context, ref, existing: s),
                        ),
                        IconButton(
                          icon: const Icon(Icons.delete_outline),
                          onPressed: () => _confirmDelete(context, ref, s),
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

  Future<void> _uploadIcon(
      BuildContext context, WidgetRef ref, ServiceModel s) async {
    final File? file = await pickAndCompressImage();
    if (file == null) return;
    try {
      await ref.read(adminRepositoryProvider).uploadServiceIcon(s.id, file);
      ref.invalidate(adminServicesProvider);
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('$e')));
      }
    }
  }

  Future<void> _confirmDelete(
      BuildContext context, WidgetRef ref, ServiceModel s) async {
    final l10n = AppLocalizations.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l10n.t('admin.deleteService')),
        content: Text(s.key),
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
      await ref.read(adminRepositoryProvider).deleteService(s.id);
      ref.invalidate(adminServicesProvider);
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('$e')));
      }
    }
  }

  Future<void> _showEditor(BuildContext context, WidgetRef ref,
      {ServiceModel? existing}) async {
    await showDialog<void>(
      context: context,
      builder: (_) => _ServiceEditor(existing: existing),
    );
  }
}

class _ServiceEditor extends ConsumerStatefulWidget {
  const _ServiceEditor({this.existing});
  final ServiceModel? existing;

  @override
  ConsumerState<_ServiceEditor> createState() => _ServiceEditorState();
}

class _ServiceEditorState extends ConsumerState<_ServiceEditor> {
  late TextEditingController _keyCtrl;
  late TextEditingController _priceCtrl;
  late TextEditingController _sortCtrl;
  late Map<String, TextEditingController> _names;
  late Map<String, TextEditingController> _descs;
  late bool _requiresCar;
  late bool _isActive;
  bool _submitting = false;
  String? _error;

  static const _locales = ['en', 'fa', 'de'];

  @override
  void initState() {
    super.initState();
    final e = widget.existing;
    _keyCtrl = TextEditingController(text: e?.key ?? '');
    _priceCtrl = TextEditingController(text: (e?.basePrice ?? 0).toString());
    _sortCtrl = TextEditingController(text: (e?.sortOrder ?? 0).toString());
    _names = {
      for (final l in _locales)
        l: TextEditingController(text: e?.nameI18n[l] ?? '')
    };
    _descs = {
      for (final l in _locales)
        l: TextEditingController(text: e?.descriptionI18n[l] ?? '')
    };
    _requiresCar = e?.requiresCar ?? false;
    _isActive = e?.isActive ?? true;
  }

  @override
  void dispose() {
    _keyCtrl.dispose();
    _priceCtrl.dispose();
    _sortCtrl.dispose();
    for (final c in _names.values) {
      c.dispose();
    }
    for (final c in _descs.values) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> _save() async {
    final price = double.tryParse(_priceCtrl.text.trim());
    final sort = int.tryParse(_sortCtrl.text.trim());
    if (_keyCtrl.text.trim().isEmpty || price == null || sort == null) {
      setState(() => _error = 'invalid input');
      return;
    }
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final model = ServiceModel(
        id: widget.existing?.id ?? 0,
        key: _keyCtrl.text.trim(),
        nameI18n: {
          for (final entry in _names.entries)
            if (entry.value.text.trim().isNotEmpty)
              entry.key: entry.value.text.trim()
        },
        descriptionI18n: {
          for (final entry in _descs.entries)
            if (entry.value.text.trim().isNotEmpty)
              entry.key: entry.value.text.trim()
        },
        icon: widget.existing?.icon,
        basePrice: price,
        sortOrder: sort,
        requiresCar: _requiresCar,
        isActive: _isActive,
      );
      await ref.read(adminRepositoryProvider).upsertService(model);
      ref.invalidate(adminServicesProvider);
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
          ? l10n.t('admin.addService')
          : l10n.t('admin.editService')),
      content: SizedBox(
        width: 480,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: _keyCtrl,
                decoration: InputDecoration(
                  labelText: l10n.t('admin.serviceKey'),
                ),
                enabled: widget.existing == null,
              ),
              I18nFieldEditor(
                title: l10n.t('admin.serviceName'),
                controllers: _names,
              ),
              I18nFieldEditor(
                title: l10n.t('admin.serviceDescription'),
                controllers: _descs,
                multiline: true,
              ),
              TextField(
                controller: _priceCtrl,
                keyboardType:
                    const TextInputType.numberWithOptions(decimal: true),
                decoration: InputDecoration(
                  labelText: l10n.t('admin.basePrice'),
                  suffixText: '€',
                ),
              ),
              TextField(
                controller: _sortCtrl,
                keyboardType: TextInputType.number,
                decoration: InputDecoration(
                  labelText: l10n.t('admin.sortOrder'),
                ),
              ),
              SwitchListTile(
                value: _requiresCar,
                onChanged: (v) => setState(() => _requiresCar = v),
                title: Text(l10n.t('admin.requiresCar')),
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
