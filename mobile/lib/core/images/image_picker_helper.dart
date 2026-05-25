import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_image_compress/flutter_image_compress.dart';
import 'package:image_picker/image_picker.dart';

/// Picks an image from the gallery (or camera) and compresses it to a
/// reasonable size for upload. Returns null when the user cancels.
///
/// Errors are caught and logged so the caller never crashes on permission
/// issues — they just get null and can show a snackbar.
Future<File?> pickAndCompressImage({
  ImageSource source = ImageSource.gallery,
  int maxWidth = 1280,
  int quality = 80,
}) async {
  try {
    final picker = ImagePicker();
    final xfile = await picker.pickImage(source: source);
    if (xfile == null) return null;
    final input = File(xfile.path);
    final out =
        '${Directory.systemTemp.path}/putzfee_${DateTime.now().millisecondsSinceEpoch}.jpg';
    final compressed = await FlutterImageCompress.compressAndGetFile(
      input.path,
      out,
      quality: quality,
      minWidth: maxWidth,
      minHeight: maxWidth,
    );
    if (compressed == null) return input;
    return File(compressed.path);
  } catch (e) {
    debugPrint('image pick/compress failed: $e');
    return null;
  }
}
