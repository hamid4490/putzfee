import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/localization/app_localizations.dart';
import '../ai_assistant/presentation/screens/ai_assistant_screen.dart';
import '../orders/presentation/screens/user_orders_screen.dart';
import '../profile/presentation/screens/profile_screen.dart';
import 'user_home_screen.dart';

class UserMainScreen extends ConsumerStatefulWidget {
  const UserMainScreen({super.key});

  @override
  ConsumerState<UserMainScreen> createState() => _UserMainScreenState();
}

class _UserMainScreenState extends ConsumerState<UserMainScreen> {
  int _selectedIndex = 0;

  final List<Widget> _screens = const [
    UserHomeScreen(),
    UserOrdersScreen(),
    AIAssistantScreen(),
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
            icon: const Icon(Icons.home_outlined),
            activeIcon: const Icon(Icons.home),
            label: l10n.t('nav.home'),
          ),
          BottomNavigationBarItem(
            icon: const Icon(Icons.history_outlined),
            activeIcon: const Icon(Icons.history),
            label: l10n.t('nav.orderHistory'),
          ),
          BottomNavigationBarItem(
            icon: const Icon(Icons.smart_toy_outlined),
            activeIcon: const Icon(Icons.smart_toy),
            label: l10n.t('nav.aiAssistant'),
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
