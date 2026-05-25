import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/models/car_model.dart';
import '../../../core/network/api_client.dart';

class CarsRepository {
  CarsRepository(this._api);

  final ApiClient _api;

  Future<List<CarModel>> list() async {
    final data = await _api.get<List<dynamic>>('/user/cars');
    return data
        .map((e) => CarModel.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  Future<CarModel> create({
    required String brand,
    required String model,
    String? plate,
    String? color,
  }) async {
    final data = await _api.post<Map<String, dynamic>>(
      '/user/cars',
      body: {
        'brand': brand,
        'model': model,
        if (plate != null && plate.isNotEmpty) 'plate': plate,
        if (color != null && color.isNotEmpty) 'color': color,
      },
    );
    return CarModel.fromJson(data);
  }

  Future<CarModel> update({
    required int id,
    String? brand,
    String? model,
    String? plate,
    String? color,
  }) async {
    final data = await _api.patch<Map<String, dynamic>>(
      '/user/cars/$id',
      body: {
        if (brand != null) 'brand': brand,
        if (model != null) 'model': model,
        if (plate != null) 'plate': plate,
        if (color != null) 'color': color,
      },
    );
    return CarModel.fromJson(data);
  }

  Future<void> delete(int id) async {
    await _api.delete<dynamic>('/user/cars/$id');
  }
}

final carsRepositoryProvider = Provider<CarsRepository>((ref) {
  return CarsRepository(ref.watch(apiClientProvider));
});

final carsProvider = FutureProvider.autoDispose<List<CarModel>>((ref) async {
  return ref.watch(carsRepositoryProvider).list();
});
