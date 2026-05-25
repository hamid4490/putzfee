import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/network/api_client.dart';
import '../../../core/storage/token_storage.dart';
import 'auth_models.dart';

/// Thin wrapper around `/auth/*` endpoints. The data layer is intentionally
/// stateless — state lives in the [authProvider].
class AuthRepository {
  AuthRepository(this._api, this._storage);

  final ApiClient _api;
  final TokenStorage _storage;

  Future<TokenPair> login({
    required String phone,
    required String password,
  }) async {
    final data = await _api.post<Map<String, dynamic>>(
      '/auth/login',
      body: {'phone': phone, 'password': password},
    );
    final pair = TokenPair.fromJson(data);
    await _storage.save(
      accessToken: pair.accessToken,
      refreshToken: pair.refreshToken,
      userId: pair.userId,
      isAdmin: pair.isAdmin,
    );
    return pair;
  }

  Future<TokenPair> register({
    required String phone,
    required String fullName,
    required String password,
    String? address,
    String locale = 'en',
  }) async {
    final data = await _api.post<Map<String, dynamic>>(
      '/auth/register',
      body: {
        'phone': phone,
        'full_name': fullName,
        'password': password,
        'locale': locale,
        if (address != null && address.isNotEmpty) 'address': address,
      },
    );
    final pair = TokenPair.fromJson(data);
    await _storage.save(
      accessToken: pair.accessToken,
      refreshToken: pair.refreshToken,
      userId: pair.userId,
      isAdmin: pair.isAdmin,
    );
    return pair;
  }

  Future<AppUser> me() async {
    final data = await _api.get<Map<String, dynamic>>('/auth/me');
    return AppUser.fromJson(data);
  }

  Future<void> logout() async {
    final refresh = await _storage.readRefresh();
    if (refresh != null && refresh.isNotEmpty) {
      try {
        await _api.post<dynamic>('/auth/logout',
            body: {'refresh_token': refresh});
      } catch (_) {
        // Logout is best-effort; clear local state regardless.
      }
    }
    await _storage.clear();
  }

  Future<void> forgotPassword(String phone) async {
    await _api.post<dynamic>('/auth/forgot-password', body: {'phone': phone});
  }

  Future<void> resetPassword({
    required String token,
    required String newPassword,
  }) async {
    await _api.post<dynamic>(
      '/auth/reset-password',
      body: {'token': token, 'new_password': newPassword},
    );
  }
}

final authRepositoryProvider = Provider<AuthRepository>((ref) {
  final api = ref.watch(apiClientProvider);
  final storage = ref.watch(tokenStorageProvider);
  return AuthRepository(api, storage);
});
