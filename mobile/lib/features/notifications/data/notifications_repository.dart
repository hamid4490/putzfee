import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/models/notification_model.dart';
import '../../../core/network/api_client.dart';

class NotificationsRepository {
  NotificationsRepository(this._api);

  final ApiClient _api;

  Future<List<NotificationModel>> list({int limit = 50, int offset = 0}) async {
    final data = await _api.get<List<dynamic>>(
      '/user/notifications',
      query: {'limit': limit, 'offset': offset},
    );
    return data
        .map((e) =>
            NotificationModel.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  Future<void> markRead(int id) async {
    await _api.post<dynamic>('/user/notifications/$id/read');
  }

  Future<void> markAllRead() async {
    await _api.post<dynamic>('/user/notifications/read-all');
  }

  Future<void> registerDevice({
    required String token,
    String platform = 'android',
  }) async {
    await _api.post<dynamic>(
      '/user/devices',
      body: {'token': token, 'platform': platform},
    );
  }

  Future<void> unregisterDevice(String token) async {
    await _api.delete<dynamic>('/user/devices/$token');
  }
}

final notificationsRepositoryProvider =
    Provider<NotificationsRepository>((ref) {
  return NotificationsRepository(ref.watch(apiClientProvider));
});

final notificationsProvider =
    FutureProvider.autoDispose<List<NotificationModel>>((ref) async {
  return ref.watch(notificationsRepositoryProvider).list();
});
