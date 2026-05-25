import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/models/order_model.dart';
import '../../../core/models/promotion_model.dart';
import '../../../core/models/service_model.dart';
import '../../../core/network/api_client.dart';

class AdminOrdersPage {
  AdminOrdersPage({
    required this.items,
    required this.total,
    required this.page,
    required this.pageSize,
  });

  factory AdminOrdersPage.fromJson(Map<String, dynamic> json) =>
      AdminOrdersPage(
        items: (json['items'] as List? ?? const [])
            .map((e) => OrderModel.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList(),
        total: (json['total'] as num?)?.toInt() ?? 0,
        page: (json['page'] as num?)?.toInt() ?? 1,
        pageSize: (json['page_size'] as num?)?.toInt() ?? 20,
      );

  final List<OrderModel> items;
  final int total;
  final int page;
  final int pageSize;
}

class AdminRepository {
  AdminRepository(this._api);

  final ApiClient _api;

  // ----------------- Services -----------------
  Future<List<ServiceModel>> listServices() async {
    final data = await _api.get<List<dynamic>>('/admin/services');
    return data
        .map((e) => ServiceModel.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  Future<ServiceModel> upsertService(ServiceModel service) async {
    final data = await _api.post<Map<String, dynamic>>(
      '/admin/services',
      body: service.toUpsertJson(),
    );
    return ServiceModel.fromJson(data);
  }

  Future<void> deleteService(int id) async {
    await _api.delete<dynamic>('/admin/services/$id');
  }

  Future<ServiceModel> uploadServiceIcon(int id, File file) async {
    final form = FormData.fromMap({
      'file': await MultipartFile.fromFile(file.path),
    });
    final r = await _api.raw.post<Map<String, dynamic>>(
      '/admin/services/$id/icon',
      data: form,
    );
    return ServiceModel.fromJson(r.data!);
  }

  // ----------------- Promotions -----------------
  Future<List<PromotionModel>> listPromotions() async {
    final data = await _api.get<List<dynamic>>('/admin/promotions');
    return data
        .map(
            (e) => PromotionModel.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  Future<PromotionModel> upsertPromotion(PromotionModel promo) async {
    final data = await _api.post<Map<String, dynamic>>(
      '/admin/promotions',
      body: promo.toUpsertJson(),
    );
    return PromotionModel.fromJson(data);
  }

  Future<void> deletePromotion(int id) async {
    await _api.delete<dynamic>('/admin/promotions/$id');
  }

  Future<PromotionModel> uploadPromotionImage(int id, File file) async {
    final form = FormData.fromMap({
      'file': await MultipartFile.fromFile(file.path),
    });
    final r = await _api.raw.post<Map<String, dynamic>>(
      '/admin/promotions/$id/image',
      data: form,
    );
    return PromotionModel.fromJson(r.data!);
  }

  // ----------------- Orders -----------------
  Future<AdminOrdersPage> listActive({
    String? statusFilter,
    int page = 1,
    int pageSize = 20,
  }) async {
    final data = await _api.get<Map<String, dynamic>>(
      '/admin/orders',
      query: {
        if (statusFilter != null) 'status': statusFilter,
        'page': page,
        'page_size': pageSize,
      },
    );
    return AdminOrdersPage.fromJson(data);
  }

  Future<AdminOrdersPage> listHistory({int page = 1, int pageSize = 20}) async {
    final data = await _api.get<Map<String, dynamic>>(
      '/admin/orders/history',
      query: {'page': page, 'page_size': pageSize},
    );
    return AdminOrdersPage.fromJson(data);
  }

  Future<OrderModel> getOrder(int id) async {
    final data = await _api.get<Map<String, dynamic>>('/admin/orders/$id');
    return OrderModel.fromJson(data);
  }

  Future<OrderModel> setPrice({
    required int orderId,
    required double totalPrice,
    required int execDurationMinutes,
  }) async {
    final data = await _api.post<Map<String, dynamic>>(
      '/admin/orders/$orderId/price',
      body: {
        'total_price': totalPrice,
        'exec_duration_minutes': execDurationMinutes,
      },
    );
    return OrderModel.fromJson(data);
  }

  Future<OrderModel> startOrder(int orderId) async {
    final data = await _api
        .post<Map<String, dynamic>>('/admin/orders/$orderId/start');
    return OrderModel.fromJson(data);
  }

  Future<OrderModel> finishOrder(int orderId) async {
    final data = await _api
        .post<Map<String, dynamic>>('/admin/orders/$orderId/finish');
    return OrderModel.fromJson(data);
  }

  Future<OrderModel> cancelOrder(int orderId, {String? reason}) async {
    final data = await _api.post<Map<String, dynamic>>(
      '/admin/orders/$orderId/cancel',
      body: {if (reason != null) 'reason': reason},
    );
    return OrderModel.fromJson(data);
  }
}

final adminRepositoryProvider = Provider<AdminRepository>((ref) {
  return AdminRepository(ref.watch(apiClientProvider));
});

final adminServicesProvider =
    FutureProvider.autoDispose<List<ServiceModel>>((ref) async {
  return ref.watch(adminRepositoryProvider).listServices();
});

final adminPromotionsProvider =
    FutureProvider.autoDispose<List<PromotionModel>>((ref) async {
  return ref.watch(adminRepositoryProvider).listPromotions();
});

final adminActiveOrdersProvider =
    FutureProvider.autoDispose<AdminOrdersPage>((ref) async {
  return ref.watch(adminRepositoryProvider).listActive();
});

final adminHistoryProvider =
    FutureProvider.autoDispose<AdminOrdersPage>((ref) async {
  return ref.watch(adminRepositoryProvider).listHistory();
});

final adminOrderDetailProvider =
    FutureProvider.autoDispose.family<OrderModel, int>((ref, id) async {
  return ref.watch(adminRepositoryProvider).getOrder(id);
});
