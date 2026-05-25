import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'main.dart';

/// Entry point for the **admin** flavor.
///
/// Usage:
/// ```bash
/// flutter run --flavor admin -t lib/main_admin.dart
/// ```
void main() {
  runApp(const ProviderScope(child: PutzfeeApp()));
}
