import 'dart:io';

import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../features/notifications/data/notifications_repository.dart';

/// Top-level handler for background FCM messages. Must be a top-level
/// function annotated with `@pragma('vm:entry-point')`.
@pragma('vm:entry-point')
Future<void> firebaseBackgroundHandler(RemoteMessage message) async {
  // No app state available here — only the system tray notification.
  debugPrint('Background FCM: ${message.messageId}');
}

class PushService {
  PushService(this._repo);

  final NotificationsRepository _repo;
  final FlutterLocalNotificationsPlugin _local =
      FlutterLocalNotificationsPlugin();

  bool _initialized = false;
  String? _lastToken;

  /// Initializes Firebase + local notifications + FCM token registration.
  /// Safe to call multiple times. Silently disables itself if Firebase
  /// is not configured (e.g. no google-services.json).
  Future<void> init() async {
    if (_initialized) return;
    try {
      await Firebase.initializeApp();
    } catch (e) {
      debugPrint('Firebase not configured — push disabled: $e');
      return;
    }

    try {
      const initAndroid =
          AndroidInitializationSettings('@mipmap/ic_launcher');
      const initIOS = DarwinInitializationSettings();
      const settings = InitializationSettings(
        android: initAndroid,
        iOS: initIOS,
      );
      await _local.initialize(settings);

      const channel = AndroidNotificationChannel(
        'putzfee_default',
        'Putzfee',
        description: 'Order updates and announcements',
        importance: Importance.high,
      );
      await _local
          .resolvePlatformSpecificImplementation<
              AndroidFlutterLocalNotificationsPlugin>()
          ?.createNotificationChannel(channel);
    } catch (e) {
      debugPrint('local notifications init failed: $e');
    }

    try {
      final settings = await FirebaseMessaging.instance
          .requestPermission(alert: true, badge: true, sound: true);
      debugPrint('FCM permission: ${settings.authorizationStatus}');
    } catch (e) {
      debugPrint('FCM permission request failed: $e');
    }

    FirebaseMessaging.onBackgroundMessage(firebaseBackgroundHandler);
    FirebaseMessaging.onMessage.listen(_onForeground);

    try {
      final token = await FirebaseMessaging.instance.getToken();
      if (token != null && token != _lastToken) {
        _lastToken = token;
        await _registerToken(token);
      }
      FirebaseMessaging.instance.onTokenRefresh.listen(_registerToken);
    } catch (e) {
      debugPrint('FCM token fetch failed: $e');
    }

    _initialized = true;
  }

  Future<void> _registerToken(String token) async {
    try {
      String platform = 'android';
      if (Platform.isIOS) platform = 'ios';
      await _repo.registerDevice(token: token, platform: platform);
    } catch (e) {
      debugPrint('register device token failed: $e');
    }
  }

  Future<void> unregister() async {
    if (_lastToken != null) {
      try {
        await _repo.unregisterDevice(_lastToken!);
      } catch (_) {}
      _lastToken = null;
    }
    try {
      await FirebaseMessaging.instance.deleteToken();
    } catch (_) {}
  }

  void _onForeground(RemoteMessage message) {
    final n = message.notification;
    if (n == null) return;
    const androidDetails = AndroidNotificationDetails(
      'putzfee_default',
      'Putzfee',
      channelDescription: 'Order updates and announcements',
      importance: Importance.high,
      priority: Priority.high,
    );
    const details = NotificationDetails(
      android: androidDetails,
      iOS: DarwinNotificationDetails(),
    );
    _local.show(
      n.hashCode,
      n.title,
      n.body,
      details,
    );
  }
}

final pushServiceProvider = Provider<PushService>((ref) {
  final repo = ref.watch(notificationsRepositoryProvider);
  return PushService(repo);
});
