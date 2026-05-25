// ignore_for_file: deprecated_member_use
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:latlong2/latlong.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/models/car_model.dart';
import '../../../../core/models/service_model.dart';
import '../../../../core/network/api_exception.dart';
import '../../../cars/data/cars_repository.dart';
import '../../../map/presentation/location_picker_screen.dart';
import '../../data/orders_repository.dart';
import '../../data/public_repository.dart';

class NewOrderScreen extends ConsumerStatefulWidget {
  const NewOrderScreen({super.key});

  @override
  ConsumerState<NewOrderScreen> createState() => _NewOrderScreenState();
}

class _NewOrderScreenState extends ConsumerState<NewOrderScreen> {
  final _formKey = GlobalKey<FormState>();
  final _addressCtrl = TextEditingController();
  final _notesCtrl = TextEditingController();
  final _selectedServices = <ServiceModel>{};
  CarModel? _selectedCar;
  LatLng? _pickedLocation;
  bool _submitting = false;
  String? _error;

  @override
  void dispose() {
    _addressCtrl.dispose();
    _notesCtrl.dispose();
    super.dispose();
  }

  bool get _requiresCar => _selectedServices.any((s) => s.requiresCar);

  Future<void> _pickLocation() async {
    final result = await Navigator.of(context).push<LatLng>(
      MaterialPageRoute(
        builder: (_) => LocationPickerScreen(initial: _pickedLocation),
      ),
    );
    if (result != null) {
      setState(() => _pickedLocation = result);
    }
  }

  Future<void> _submit() async {
    final l10n = AppLocalizations.of(context);
    if (_selectedServices.isEmpty) {
      setState(() => _error = l10n.t('order.selectAtLeastOneService'));
      return;
    }
    if (_requiresCar && _selectedCar == null) {
      setState(() => _error = l10n.t('order.carRequired'));
      return;
    }
    if (!_formKey.currentState!.validate()) return;

    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final repo = ref.read(ordersRepositoryProvider);
      final order = await repo.createOrder(
        serviceKeys: _selectedServices.map((s) => s.key).toList(),
        carId: _selectedCar?.id,
        latitude: _pickedLocation?.latitude,
        longitude: _pickedLocation?.longitude,
        addressText: _addressCtrl.text.trim().isEmpty
            ? null
            : _addressCtrl.text.trim(),
        notes: _notesCtrl.text.trim().isEmpty ? null : _notesCtrl.text.trim(),
      );
      if (!mounted) return;
      ref.invalidate(myOrdersProvider);
      context.go('/orders/${order.id}');
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
    final servicesAsync = ref.watch(publicHomeProvider);
    final carsAsync = ref.watch(carsProvider);

    return Scaffold(
      appBar: AppBar(title: Text(l10n.t('order.newOrder'))),
      body: Form(
        key: _formKey,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Text(l10n.t('order.services'), style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            servicesAsync.when(
              loading: () =>
                  const Center(child: CircularProgressIndicator()),
              error: (e, _) => Text(e is ApiException ? e.message : '$e'),
              data: (payload) {
                if (payload.services.isEmpty) {
                  return Text(l10n.t('common.empty'));
                }
                return Column(
                  children: payload.services.map((s) {
                    final selected = _selectedServices.contains(s);
                    return CheckboxListTile(
                      value: selected,
                      onChanged: (v) => setState(() {
                        if (v == true) {
                          _selectedServices.add(s);
                        } else {
                          _selectedServices.remove(s);
                        }
                      }),
                      title: Text(s.nameFor(code)),
                      subtitle: s.basePrice > 0
                          ? Text('${s.basePrice.toStringAsFixed(2)} €')
                          : null,
                    );
                  }).toList(),
                );
              },
            ),
            const SizedBox(height: 16),
            if (_requiresCar) ...[
              Text(l10n.t('order.selectCar'),
                  style: theme.textTheme.titleMedium),
              const SizedBox(height: 8),
              carsAsync.when(
                loading: () =>
                    const Center(child: CircularProgressIndicator()),
                error: (e, _) => Text(e is ApiException ? e.message : '$e'),
                data: (cars) {
                  if (cars.isEmpty) {
                    return Card(
                      child: ListTile(
                        title: Text(l10n.t('cars.empty')),
                        trailing: const Icon(Icons.chevron_right),
                        onTap: () => context.push('/cars'),
                      ),
                    );
                  }
                  return Column(
                    children: cars.map((c) {
                      return RadioListTile<int>(
                        value: c.id,
                        groupValue: _selectedCar?.id,
                        onChanged: (_) =>
                            setState(() => _selectedCar = c),
                        title: Text(c.displayName),
                        subtitle: c.color != null && c.color!.isNotEmpty
                            ? Text(c.color!)
                            : null,
                      );
                    }).toList(),
                  );
                },
              ),
              const SizedBox(height: 16),
            ],
            Text(l10n.t('order.address'), style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            TextFormField(
              controller: _addressCtrl,
              maxLength: 500,
              decoration: InputDecoration(
                hintText: l10n.t('order.addressHint'),
                border: const OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            Card(
              child: ListTile(
                leading: const Icon(Icons.location_on_outlined),
                title: Text(_pickedLocation == null
                    ? l10n.t('order.pickLocation')
                    : '${_pickedLocation!.latitude.toStringAsFixed(5)}, '
                        '${_pickedLocation!.longitude.toStringAsFixed(5)}'),
                trailing: const Icon(Icons.chevron_right),
                onTap: _pickLocation,
              ),
            ),
            const SizedBox(height: 16),
            Text(l10n.t('order.notes'), style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            TextFormField(
              controller: _notesCtrl,
              maxLines: 3,
              maxLength: 1000,
              decoration: const InputDecoration(border: OutlineInputBorder()),
            ),
            if (_error != null) ...[
              const SizedBox(height: 8),
              Text(
                _error!,
                style: TextStyle(color: theme.colorScheme.error),
              ),
            ],
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: _submitting ? null : _submit,
              icon: _submitting
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.send),
              label: Text(l10n.t('order.submit')),
            ),
          ],
        ),
      ),
    );
  }
}

