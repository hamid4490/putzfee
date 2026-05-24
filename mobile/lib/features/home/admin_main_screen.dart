import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/localization/app_localizations.dart';
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
    _AdminPlaceholderScreen(title: 'Services'),
    _AdminPlaceholderScreen(title: 'Promotions'),
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

class _AdminPlaceholderScreen extends StatelessWidget {
  const _AdminPlaceholderScreen({required this.title});

  final String title;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(title)),
      body: Center(child: Text('$title — coming soon')),
    );
  }
}
