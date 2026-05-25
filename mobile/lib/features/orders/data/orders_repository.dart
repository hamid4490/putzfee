import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/models/order_model.dart';
import '../../../core/models/slot_model.dart';
import '../../../core/network/api_client.dart';

class OrdersRepository {
  OrdersRepository(this._api);

  final ApiClient _api;

  Future<OrderModel> createOrder({
    required List<String> serviceKeys,
    int? carId,
    double? latitude,
    double? longitude,
    String? addressText,
    String? notes,
    int? promotionId,
    String paymentType = 'cash',
  }) async {
    final data = await _api.post<Map<String, dynamic>>(
      '/orders',
      body: {
        'service_keys': serviceKeys,
        if (carId != null) 'car_id': carId,
        if (latitude != null) 'latitude': latitude,
        if (longitude != null) 'longitude': longitude,
        if (addressText != null && addressText.isNotEmpty)
          'address_text': addressText,
        if (notes != null && notes.isNotEmpty) 'notes': notes,
        if (promotionId != null) 'promotion_id': promotionId,
        'payment_type': paymentType,
      },
    );
    return OrderModel.fromJson(data);
  }

  Future<List<OrderModel>> listMyOrders({
    String? statusFilter,
    int limit = 50,
    int offset = 0,
  }) async {
    final data = await _api.get<List<dynamic>>(
      '/orders',
      query: {
        if (statusFilter != null) 'status': statusFilter,
        'limit': limit,
        'offset': offset,
      },
    );
    return data
        .map((e) => OrderModel.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  Future<OrderModel> getOrder(int id) async {
    final data = await _api.get<Map<String, dynamic>>('/orders/$id');
    return OrderModel.fromJson(data);
  }

  Future<List<SlotModel>> listSlots(int orderId) async {
    final data = await _api.get<List<dynamic>>('/orders/$orderId/slots');
    return data
        .map((e) => SlotModel.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  Future<OrderModel> cancelOrder(int id, {String? reason}) async {
    final data = await _api.post<Map<String, dynamic>>(
      '/orders/$id/cancel',
      body: {if (reason != null) 'reason': reason},
    );
    return OrderModel.fromJson(data);
  }

  Future<void> submitReview({
    required int orderId,
    required int rating,
    String? comment,
  }) async {
    await _api.post<dynamic>(
      '/orders/$orderId/review',
      body: {
        'rating': rating,
        if (comment != null && comment.isNotEmpty) 'comment': comment,
      },
    );
  }
}

final ordersRepositoryProvider = Provider<OrdersRepository>((ref) {
  return OrdersRepository(ref.watch(apiClientProvider));
});

final myOrdersProvider =
    FutureProvider.autoDispose<List<OrderModel>>((ref) async {
  return ref.watch(ordersRepositoryProvider).listMyOrders();
});

final orderDetailProvider = FutureProvider.autoDispose
    .family<OrderModel, int>((ref, id) async {
  return ref.watch(ordersRepositoryProvider).getOrder(id);
});

final orderSlotsProvider = FutureProvider.autoDispose
    .family<List<SlotModel>, int>((ref, id) async {
  return ref.watch(ordersRepositoryProvider).listSlots(id);
});
