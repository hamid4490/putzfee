import 'package:flutter/material.dart';

/// Reusable editor for `Map<langCode, String>` style i18n fields.
///
/// The caller provides one [TextEditingController] per locale and we render
/// labeled inputs vertically.
class I18nFieldEditor extends StatelessWidget {
  const I18nFieldEditor({
    super.key,
    required this.title,
    required this.controllers,
    this.multiline = false,
  });

  final String title;
  final Map<String, TextEditingController> controllers;
  final bool multiline;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: 12),
        Text(title, style: theme.textTheme.titleSmall),
        const SizedBox(height: 4),
        ...controllers.entries.map((e) => Padding(
              padding: const EdgeInsets.only(bottom: 4),
              child: TextField(
                controller: e.value,
                maxLines: multiline ? 3 : 1,
                decoration: InputDecoration(
                  isDense: true,
                  labelText: e.key.toUpperCase(),
                  border: const OutlineInputBorder(),
                ),
              ),
            )),
      ],
    );
  }
}
