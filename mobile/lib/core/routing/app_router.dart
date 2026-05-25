import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../features/admin/presentation/screens/admin_order_detail_screen.dart';
import '../../features/auth/presentation/providers/auth_provider.dart';
import '../../features/auth/presentation/screens/forgot_password_screen.dart';
import '../../features/auth/presentation/screens/login_screen.dart';
import '../../features/auth/presentation/screens/register_screen.dart';
import '../../features/auth/presentation/screens/reset_password_screen.dart';
import '../../features/auth/presentation/screens/splash_screen.dart';
import '../../features/cars/presentation/screens/cars_screen.dart';
import '../../features/home/admin_main_screen.dart';
import '../../features/home/user_main_screen.dart';
import '../../features/notifications/presentation/screens/notifications_screen.dart';
import '../../features/orders/presentation/screens/new_order_screen.dart';
import '../../features/orders/presentation/screens/user_order_detail_screen.dart';

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
      const publicPaths = <String>{
        '/login',
        '/register',
        '/forgot-password',
        '/reset-password',
      };
      switch (auth.status) {
        case AuthStatus.unknown:
          return loc == '/' ? null : '/';
        case AuthStatus.unauthenticated:
          if (publicPaths.contains(loc)) return null;
          return '/login';
        case AuthStatus.authenticated:
          if (loc == '/' || publicPaths.contains(loc)) {
            return auth.isAdmin ? '/admin' : '/home';
          }
          if (loc.startsWith('/admin') && !auth.isAdmin) return '/home';
          return null;
      }
    },
    routes: [
      GoRoute(path: '/', builder: (_, __) => const SplashScreen()),
      GoRoute(path: '/login', builder: (_, __) => const LoginScreen()),
      GoRoute(path: '/register', builder: (_, __) => const RegisterScreen()),
      GoRoute(
        path: '/forgot-password',
        builder: (_, __) => const ForgotPasswordScreen(),
      ),
      GoRoute(
        path: '/reset-password',
        builder: (_, __) => const ResetPasswordScreen(),
      ),
      GoRoute(path: '/home', builder: (_, __) => const UserMainScreen()),
      GoRoute(path: '/cars', builder: (_, __) => const CarsScreen()),
      GoRoute(
        path: '/orders/new',
        builder: (_, __) => const NewOrderScreen(),
      ),
      GoRoute(
        path: '/orders/:id',
        builder: (_, s) => UserOrderDetailScreen(
          orderId: int.parse(s.pathParameters['id']!),
        ),
      ),
      GoRoute(
        path: '/notifications',
        builder: (_, __) => const NotificationsScreen(),
      ),
      GoRoute(path: '/admin', builder: (_, __) => const AdminMainScreen()),
      GoRoute(
        path: '/admin/orders/:id',
        builder: (_, s) => AdminOrderDetailScreen(
          orderId: int.parse(s.pathParameters['id']!),
        ),
      ),
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
