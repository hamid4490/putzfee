import 'package:flutter/foundation.dart';

/// Compile-time configuration for the PUTZFEE mobile app.
///
/// Override with `--dart-define=API_BASE_URL=https://api.example.com`.
class AppConfig {
  const AppConfig._();

  static const String apiBaseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'http://10.0.2.2:8000',
  );

  static const String mapboxAccessToken = String.fromEnvironment(
    'MAPBOX_TOKEN',
    defaultValue: '',
  );

  /// Business timezone — matches the server (`SERVER_TIMEZONE`).
  static const String serverTimezone = String.fromEnvironment(
    'SERVER_TIMEZONE',
    defaultValue: 'Europe/Berlin',
  );

  /// Default map center when no location is selected (Berlin, DE).
  static const double defaultLatitude = 52.5200;
  static const double defaultLongitude = 13.4050;

  /// Mapbox raster tile URL template. Falls back to OpenStreetMap
  /// when no Mapbox token is provided.
  static String get mapTileUrl {
    if (mapboxAccessToken.isEmpty) {
      return 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';
    }
    return 'https://api.mapbox.com/styles/v1/mapbox/streets-v12/tiles/'
        '256/{z}/{x}/{y}@2x?access_token=$mapboxAccessToken';
  }

  static const String mapAttribution =
      '© Mapbox / OpenStreetMap contributors';

  static bool get isDebug => kDebugMode;
}
