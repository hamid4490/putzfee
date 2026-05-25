import 'package:flutter/material.dart';

import '../../../../core/localization/app_localizations.dart';

class SplashScreen extends StatelessWidget {
  const SplashScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.cleaning_services_rounded,
                size: 72,
                color: Theme.of(context).colorScheme.primary,
              ),
              const SizedBox(height: 16),
              Text(l10n.t('app_title'),
                  style: Theme.of(context).textTheme.headlineMedium),
              const SizedBox(height: 8),
              Text(l10n.t('tagline'),
                  style: Theme.of(context).textTheme.bodyMedium),
              const SizedBox(height: 32),
              const CircularProgressIndicator(),
            ],
          ),
        ),
      ),
    );
  }
}
