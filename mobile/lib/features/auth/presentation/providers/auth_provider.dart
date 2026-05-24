import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/storage/token_storage.dart';
import '../../data/auth_models.dart';
import '../../data/auth_repository.dart';

/// Top-level auth status used by the router to decide whether to gate.
enum AuthStatus { unknown, unauthenticated, authenticated }

class AuthState {
  AuthState({
    required this.status,
    this.user,
    this.isAdmin = false,
    this.error,
  });

  factory AuthState.unknown() => AuthState(status: AuthStatus.unknown);
  factory AuthState.unauthenticated({String? error}) =>
      AuthState(status: AuthStatus.unauthenticated, error: error);
  factory AuthState.authenticated(AppUser user) => AuthState(
        status: AuthStatus.authenticated,
        user: user,
        isAdmin: user.isAdmin,
      );

  final AuthStatus status;
  final AppUser? user;
  final bool isAdmin;
  final String? error;

  bool get isAuthenticated => status == AuthStatus.authenticated;

  AuthState copyWith({
    AuthStatus? status,
    AppUser? user,
    bool? isAdmin,
    String? error,
  }) {
    return AuthState(
      status: status ?? this.status,
      user: user ?? this.user,
      isAdmin: isAdmin ?? this.isAdmin,
      error: error,
    );
  }
}

class AuthController extends StateNotifier<AuthState> {
  AuthController(this._repo, this._storage) : super(AuthState.unknown()) {
    _bootstrap();
  }

  final AuthRepository _repo;
  final TokenStorage _storage;

  Future<void> _bootstrap() async {
    final access = await _storage.readAccess();
    if (access == null || access.isEmpty) {
      state = AuthState.unauthenticated();
      return;
    }
    try {
      final me = await _repo.me();
      state = AuthState.authenticated(me);
    } catch (e) {
      debugPrint('auth bootstrap failed: $e');
      await _storage.clear();
      state = AuthState.unauthenticated();
    }
  }

  Future<void> login({required String phone, required String password}) async {
    state = state.copyWith(status: AuthStatus.unknown);
    try {
      await _repo.login(phone: phone, password: password);
      final me = await _repo.me();
      state = AuthState.authenticated(me);
    } catch (e) {
      state = AuthState.unauthenticated(error: '$e');
      rethrow;
    }
  }

  Future<void> register({
    required String phone,
    required String fullName,
    required String password,
    String? address,
    String locale = 'en',
  }) async {
    state = state.copyWith(status: AuthStatus.unknown);
    try {
      await _repo.register(
        phone: phone,
        fullName: fullName,
        password: password,
        address: address,
        locale: locale,
      );
      final me = await _repo.me();
      state = AuthState.authenticated(me);
    } catch (e) {
      state = AuthState.unauthenticated(error: '$e');
      rethrow;
    }
  }

  Future<void> logout() async {
    await _repo.logout();
    state = AuthState.unauthenticated();
  }
}

final authProvider =
    StateNotifierProvider<AuthController, AuthState>((ref) {
  final repo = ref.watch(authRepositoryProvider);
  final storage = ref.watch(tokenStorageProvider);
  return AuthController(repo, storage);
});
