import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Supported locales for PUTZFEE.
///
/// Order matters — the first entry is the default fallback.
const List<Locale> supportedLocales = <Locale>[
  Locale('en'),
  Locale('fa'),
  Locale('de'),
];

/// In-memory holder for JSON translations of a single locale.
class AppLocalizations {
  AppLocalizations(this.locale, this._strings);

  final Locale locale;
  final Map<String, String> _strings;

  static AppLocalizations of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations)!;
  }

  /// Returns the translation for [key], substituting `{var}` placeholders
  /// using [args]. Falls back to the key itself when missing.
  String t(String key, {Map<String, Object?>? args}) {
    var value = _strings[key] ?? key;
    if (args != null) {
      args.forEach((k, v) {
        value = value.replaceAll('{$k}', '${v ?? ''}');
      });
    }
    return value;
  }

  /// Convenience alias for [t].
  String translate(String key, {Map<String, Object?>? args}) =>
      t(key, args: args);
}

class AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const AppLocalizationsDelegate();

  @override
  bool isSupported(Locale locale) {
    return supportedLocales.any((l) => l.languageCode == locale.languageCode);
  }

  @override
  Future<AppLocalizations> load(Locale locale) async {
    final code = isSupported(locale) ? locale.languageCode : 'en';
    final raw = await rootBundle.loadString('assets/i18n/$code.json');
    final decoded = json.decode(raw) as Map<String, dynamic>;
    final strings = decoded.map((k, v) => MapEntry(k, v.toString()));
    return AppLocalizations(Locale(code), strings);
  }

  @override
  bool shouldReload(AppLocalizationsDelegate old) => false;
}

const _kLocalePrefsKey = 'app.locale';

/// Notifier that persists the user's locale choice across launches.
class LocaleNotifier extends StateNotifier<Locale?> {
  LocaleNotifier() : super(null) {
    _load();
  }

  Future<void> _load() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final code = prefs.getString(_kLocalePrefsKey);
      if (code != null && code.isNotEmpty) {
        state = Locale(code);
      }
    } catch (e) {
      debugPrint('locale load failed: $e');
    }
  }

  Future<void> setLocale(Locale? locale) async {
    state = locale;
    final prefs = await SharedPreferences.getInstance();
    if (locale == null) {
      await prefs.remove(_kLocalePrefsKey);
    } else {
      await prefs.setString(_kLocalePrefsKey, locale.languageCode);
    }
  }
}

final localeProvider =
    StateNotifierProvider<LocaleNotifier, Locale?>((ref) => LocaleNotifier());
