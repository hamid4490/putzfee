import 'package:flutter/material.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:geolocator/geolocator.dart';
import 'package:latlong2/latlong.dart';

import '../../../core/config/app_config.dart';
import '../../../core/localization/app_localizations.dart';

/// Lightweight location picker built on flutter_map. Falls back to OSM
/// tiles if no Mapbox token is configured. Returns a [LatLng] when the
/// user taps "Use this location".
class LocationPickerScreen extends StatefulWidget {
  const LocationPickerScreen({super.key, this.initial});

  final LatLng? initial;

  @override
  State<LocationPickerScreen> createState() => _LocationPickerScreenState();
}

class _LocationPickerScreenState extends State<LocationPickerScreen> {
  late final MapController _controller;
  late LatLng _center;
  LatLng? _picked;

  @override
  void initState() {
    super.initState();
    _controller = MapController();
    _center = widget.initial ??
        const LatLng(AppConfig.defaultLatitude, AppConfig.defaultLongitude);
    _picked = widget.initial;
  }

  Future<void> _useMyLocation() async {
    try {
      LocationPermission perm = await Geolocator.checkPermission();
      if (perm == LocationPermission.denied) {
        perm = await Geolocator.requestPermission();
      }
      if (perm == LocationPermission.deniedForever ||
          perm == LocationPermission.denied) {
        return;
      }
      final pos = await Geolocator.getCurrentPosition();
      final ll = LatLng(pos.latitude, pos.longitude);
      setState(() {
        _picked = ll;
        _center = ll;
      });
      _controller.move(ll, 15);
    } catch (_) {
      // Ignore — user can still tap-pick.
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.t('map.pickLocation')),
        actions: [
          IconButton(
            tooltip: l10n.t('map.myLocation'),
            icon: const Icon(Icons.my_location),
            onPressed: _useMyLocation,
          ),
        ],
      ),
      body: FlutterMap(
        mapController: _controller,
        options: MapOptions(
          initialCenter: _center,
          initialZoom: 13,
          onTap: (_, latlng) => setState(() => _picked = latlng),
        ),
        children: [
          TileLayer(
            urlTemplate: AppConfig.mapTileUrl,
            userAgentPackageName: 'app.putzfee.mobile',
          ),
          if (_picked != null)
            MarkerLayer(
              markers: [
                Marker(
                  width: 48,
                  height: 48,
                  point: _picked!,
                  child: const Icon(Icons.location_on,
                      size: 48, color: Colors.red),
                ),
              ],
            ),
          const RichAttributionWidget(
            attributions: [
              TextSourceAttribution(AppConfig.mapAttribution),
            ],
          ),
        ],
      ),
      bottomNavigationBar: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: FilledButton.icon(
            onPressed: _picked == null
                ? null
                : () => Navigator.of(context).pop(_picked),
            icon: const Icon(Icons.check),
            label: Text(l10n.t('map.useThisLocation')),
          ),
        ),
      ),
    );
  }
}
