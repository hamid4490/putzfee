import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/models/promotion_model.dart';
import '../../../core/models/service_model.dart';
import '../../../core/network/api_client.dart';

class PublicHomePayload {
  PublicHomePayload({required this.services, required this.promotions});
  final List<ServiceModel> services;
  final List<PromotionModel> promotions;
}

class PublicRepository {
  PublicRepository(this._api);

  final ApiClient _api;

  Future<PublicHomePayload> fetchHome() async {
    final data = await _api.get<Map<String, dynamic>>('/public/home');
    final services = (data['services'] as List? ?? const [])
        .map((e) => ServiceModel.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
    final promos = (data['promotions'] as List? ?? const [])
        .map(
            (e) => PromotionModel.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
    return PublicHomePayload(services: services, promotions: promos);
  }
}

final publicRepositoryProvider = Provider<PublicRepository>((ref) {
  return PublicRepository(ref.watch(apiClientProvider));
});

final publicHomeProvider =
    FutureProvider.autoDispose<PublicHomePayload>((ref) async {
  return ref.watch(publicRepositoryProvider).fetchHome();
});
