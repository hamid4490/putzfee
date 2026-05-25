import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/models/slot_model.dart';
import '../../../core/network/api_client.dart';

class SchedulingRepository {
  SchedulingRepository(this._api);

  final ApiClient _api;

  /// Admin: propose up to MAX_SLOTS_PER_REQUEST (2 in current config) UTC datetimes.
  Future<List<SlotModel>> proposeSlots({
    required int requestId,
    required List<DateTime> slots,
  }) async {
    final data = await _api.post<List<dynamic>>(
      '/scheduling/requests/$requestId/propose',
      body: {
        'slots': slots.map((d) => d.toUtc().toIso8601String()).toList(),
      },
    );
    return data
        .map((e) => SlotModel.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  /// User picks one of the proposed slot ids.
  Future<SlotModel> confirmSlot({
    required int requestId,
    required int slotId,
  }) async {
    final data = await _api.post<Map<String, dynamic>>(
      '/scheduling/requests/$requestId/confirm',
      body: {'schedule_slot_id': slotId},
    );
    return SlotModel.fromJson(data);
  }

  /// Admin: list confirmed appointments in [from..to] (YYYY-MM-DD, Europe/Berlin).
  Future<List<SlotModel>> availability({
    required DateTime from,
    required DateTime to,
  }) async {
    final data = await _api.get<List<dynamic>>(
      '/scheduling/availability',
      query: {
        'from_date': _fmt(from),
        'to_date': _fmt(to),
      },
    );
    return data
        .map((e) => SlotModel.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  String _fmt(DateTime d) =>
      '${d.year.toString().padLeft(4, '0')}-'
      '${d.month.toString().padLeft(2, '0')}-'
      '${d.day.toString().padLeft(2, '0')}';
}

final schedulingRepositoryProvider = Provider<SchedulingRepository>((ref) {
  return SchedulingRepository(ref.watch(apiClientProvider));
});
