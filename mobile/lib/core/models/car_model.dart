class CarModel {
  const CarModel({
    required this.id,
    required this.userId,
    required this.brand,
    required this.model,
    this.plate,
    this.color,
    this.createdAt,
  });

  factory CarModel.fromJson(Map<String, dynamic> json) => CarModel(
        id: (json['id'] as num).toInt(),
        userId: (json['user_id'] as num).toInt(),
        brand: json['brand'] as String,
        model: json['model'] as String,
        plate: json['plate'] as String?,
        color: json['color'] as String?,
        createdAt: DateTime.tryParse(json['created_at']?.toString() ?? ''),
      );

  final int id;
  final int userId;
  final String brand;
  final String model;
  final String? plate;
  final String? color;
  final DateTime? createdAt;

  String get displayName {
    final p = plate?.trim();
    final base = '$brand $model';
    if (p == null || p.isEmpty) return base;
    return '$base – $p';
  }
}
