import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../features/auth/presentation/providers/auth_provider.dart';
import '../../features/auth/presentation/screens/login_screen.dart';
import '../../features/auth/presentation/screens/register_screen.dart';
import '../../features/auth/presentation/screens/splash_screen.dart';
import '../../features/home/admin_main_screen.dart';
import '../../features/home/user_main_screen.dart';

/// GoRouter wired to [authProvider] so navigation reacts to login/logout.
final routerProvider = Provider<GoRouter>((ref) {
  final notifier = _AuthRouterNotifier(ref);
  ref.onDispose(notifier.dispose);
  return GoRouter(
    initialLocation: '/',
    refreshListenable: notifier,
    redirect: (context, state) {
      final auth = ref.read(authProvider);
      final loc = state.matchedLocation;
      switch (auth.status) {
        case AuthStatus.unknown:
          return loc == '/' ? null : '/';
        case AuthStatus.unauthenticated:
          if (loc == '/login' || loc == '/register') return null;
          return '/login';
        case AuthStatus.authenticated:
          if (loc == '/' || loc == '/login' || loc == '/register') {
            return auth.isAdmin ? '/admin' : '/home';
          }
          if (loc.startsWith('/admin') && !auth.isAdmin) return '/home';
          if (loc.startsWith('/home') && auth.isAdmin) return '/admin';
          return null;
      }
    },
    routes: [
      GoRoute(path: '/', builder: (_, __) => const SplashScreen()),
      GoRoute(path: '/login', builder: (_, __) => const LoginScreen()),
      GoRoute(path: '/register', builder: (_, __) => const RegisterScreen()),
      GoRoute(path: '/home', builder: (_, __) => const UserMainScreen()),
      GoRoute(path: '/admin', builder: (_, __) => const AdminMainScreen()),
    ],
  );
});

class _AuthRouterNotifier extends ChangeNotifier {
  _AuthRouterNotifier(this._ref) {
    _sub = _ref.listen<AuthState>(authProvider, (_, __) => notifyListeners());
  }
  final Ref _ref;
  late final ProviderSubscription<AuthState> _sub;

  @override
  void dispose() {
    _sub.close();
    super.dispose();
  }
}
