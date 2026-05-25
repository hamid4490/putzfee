import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/localization/app_localizations.dart';
import '../admin/presentation/screens/admin_orders_screen.dart';
import '../admin/presentation/screens/admin_promotions_screen.dart';
import '../admin/presentation/screens/admin_services_screen.dart';
import '../profile/presentation/screens/profile_screen.dart';
import 'admin_dashboard_screen.dart';

class AdminMainScreen extends ConsumerStatefulWidget {
  const AdminMainScreen({super.key});

  @override
  ConsumerState<AdminMainScreen> createState() => _AdminMainScreenState();
}

class _AdminMainScreenState extends ConsumerState<AdminMainScreen> {
  int _selectedIndex = 0;

  final List<Widget> _screens = const [
    AdminDashboardScreen(),
    AdminOrdersScreen(),
    AdminServicesScreen(),
    AdminPromotionsScreen(),
    ProfileScreen(),
  ];

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    return Scaffold(
      body: _screens[_selectedIndex],
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _selectedIndex,
        onTap: (i) => setState(() => _selectedIndex = i),
        type: BottomNavigationBarType.fixed,
        selectedItemColor: theme.colorScheme.primary,
        unselectedItemColor: theme.colorScheme.onSurfaceVariant,
        items: [
          BottomNavigationBarItem(
            icon: const Icon(Icons.dashboard_outlined),
            activeIcon: const Icon(Icons.dashboard),
            label: l10n.t('nav.dashboard'),
          ),
          BottomNavigationBarItem(
            icon: const Icon(Icons.receipt_long_outlined),
            activeIcon: const Icon(Icons.receipt_long),
            label: l10n.t('admin.orders'),
          ),
          BottomNavigationBarItem(
            icon: const Icon(Icons.cleaning_services_outlined),
            activeIcon: const Icon(Icons.cleaning_services),
            label: l10n.t('nav.services'),
          ),
          BottomNavigationBarItem(
            icon: const Icon(Icons.local_offer_outlined),
            activeIcon: const Icon(Icons.local_offer),
            label: l10n.t('nav.promotions'),
          ),
          BottomNavigationBarItem(
            icon: const Icon(Icons.person_outline),
            activeIcon: const Icon(Icons.person),
            label: l10n.t('nav.profile'),
          ),
        ],
      ),
    );
  }
}
