import 'package:flutter/material.dart';

import '../localization/app_localizations.dart';
import 'api_exception.dart';

/// Resolves an arbitrary error into a localised string that's safe to show
/// to the end user.
///
/// * For [ApiException]s with a known [ApiErrorCode] (timeout, no connection,
///   bad certificate), returns the matching `network.*` translation.
/// * For HTTP errors that carry a server `detail` / `message` field, returns
///   that text as-is — the backend already localises responses via the
///   `Accept-Language` header.
/// * For everything else, falls back to `common.error`.
String localiseError(BuildContext context, Object error) {
  final l10n = AppLocalizations.of(context);
  if (error is ApiException) {
    switch (error.code) {
      case ApiErrorCode.timeout:
        return l10n.t('network.timeout');
      case ApiErrorCode.noConnection:
        return l10n.t('network.noConnection');
      case ApiErrorCode.badCertificate:
        return l10n.t('network.badCertificate');
      case ApiErrorCode.cancelled:
      case ApiErrorCode.http:
      case ApiErrorCode.unknown:
        // The server already returns a translated `detail` for HTTP errors;
        // use it when present, otherwise fall back to the generic message.
        if (error.message.isNotEmpty) return error.message;
        return l10n.t('common.error');
    }
  }
  return l10n.t('common.error');
}

/// Shows the error as a SnackBar, used by auth + form screens so the user
/// gets immediate feedback even when the inline `Text(_error)` is scrolled
/// off-screen.
void showErrorSnackBar(BuildContext context, Object error) {
  final message = localiseError(context, error);
  ScaffoldMessenger.of(context)
    ..clearSnackBars()
    ..showSnackBar(
      SnackBar(
        content: Text(message),
        behavior: SnackBarBehavior.floating,
        duration: const Duration(seconds: 5),
      ),
    );
}
