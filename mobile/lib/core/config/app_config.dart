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

  static bool get isDebug => kDebugMode;
}
