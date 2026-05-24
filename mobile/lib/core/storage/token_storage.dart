import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Persists access + refresh tokens on the device using the OS keystore.
class TokenStorage {
  TokenStorage({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
            );

  final FlutterSecureStorage _storage;

  static const _kAccess = 'auth.access';
  static const _kRefresh = 'auth.refresh';
  static const _kIsAdmin = 'auth.is_admin';
  static const _kUserId = 'auth.user_id';

  Future<void> save({
    required String accessToken,
    required String refreshToken,
    required int userId,
    required bool isAdmin,
  }) async {
    await _storage.write(key: _kAccess, value: accessToken);
    await _storage.write(key: _kRefresh, value: refreshToken);
    await _storage.write(key: _kUserId, value: '$userId');
    await _storage.write(key: _kIsAdmin, value: isAdmin ? '1' : '0');
  }

  Future<void> updateTokens({
    required String accessToken,
    required String refreshToken,
  }) async {
    await _storage.write(key: _kAccess, value: accessToken);
    await _storage.write(key: _kRefresh, value: refreshToken);
  }

  Future<String?> readAccess() => _storage.read(key: _kAccess);
  Future<String?> readRefresh() => _storage.read(key: _kRefresh);

  Future<({int? userId, bool isAdmin})> readUser() async {
    final raw = await _storage.read(key: _kUserId);
    final adm = await _storage.read(key: _kIsAdmin);
    return (
      userId: raw == null ? null : int.tryParse(raw),
      isAdmin: adm == '1',
    );
  }

  Future<void> clear() async {
    try {
      await _storage.deleteAll();
    } catch (e) {
      debugPrint('secure storage clear failed: $e');
    }
  }
}

final tokenStorageProvider = Provider<TokenStorage>((ref) => TokenStorage());
