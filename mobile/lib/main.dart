import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'core/localization/app_localizations.dart';
import 'core/network/api_client.dart';
import 'core/routing/app_router.dart';
import 'core/theme/app_theme.dart';

void main() {
  runApp(const ProviderScope(child: PutzfeeApp()));
}

class PutzfeeApp extends ConsumerWidget {
  const PutzfeeApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final router = ref.watch(routerProvider);
    final themeMode = ref.watch(themeModeProvider);
    final locale = ref.watch(localeProvider);

    // Propagate locale changes to the API client.
    ref.listen<Locale?>(localeProvider, (_, next) {
      if (next != null) {
        ref.read(apiClientProvider).languageCode = next.languageCode;
      }
    });

    return MaterialApp.router(
      title: 'PUTZFEE',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.light(),
      darkTheme: AppTheme.dark(),
      themeMode: themeMode,
      locale: locale,
      supportedLocales: supportedLocales,
      localizationsDelegates: const [
        AppLocalizationsDelegate(),
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      localeResolutionCallback: (deviceLocale, supported) {
        if (deviceLocale != null) {
          for (final l in supported) {
            if (l.languageCode == deviceLocale.languageCode) return l;
          }
        }
        return supported.first;
      },
      routerConfig: router,
    );
  }
}
