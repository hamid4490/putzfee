/// Service that the user can book (e.g. car wash, apartment cleaning).
class ServiceModel {
  const ServiceModel({
    required this.id,
    required this.key,
    required this.nameI18n,
    required this.descriptionI18n,
    this.icon,
    this.basePrice = 0,
    this.sortOrder = 0,
    this.requiresCar = false,
    this.isActive = true,
  });

  factory ServiceModel.fromJson(Map<String, dynamic> json) => ServiceModel(
        id: (json['id'] as num).toInt(),
        key: json['key'] as String,
        nameI18n: Map<String, String>.from(
            (json['name_i18n'] as Map?)?.cast<String, dynamic>().map(
                      (k, v) => MapEntry(k, v.toString()),
                    ) ??
                const <String, String>{}),
        descriptionI18n: Map<String, String>.from(
            (json['description_i18n'] as Map?)?.cast<String, dynamic>().map(
                      (k, v) => MapEntry(k, v.toString()),
                    ) ??
                const <String, String>{}),
        icon: json['icon'] as String?,
        basePrice: _toDouble(json['base_price']),
        sortOrder: (json['sort_order'] as num?)?.toInt() ?? 0,
        requiresCar: (json['requires_car'] as bool?) ?? false,
        isActive: (json['is_active'] as bool?) ?? true,
      );

  final int id;
  final String key;
  final Map<String, String> nameI18n;
  final Map<String, String> descriptionI18n;
  final String? icon;
  final double basePrice;
  final int sortOrder;
  final bool requiresCar;
  final bool isActive;

  String nameFor(String languageCode) {
    return nameI18n[languageCode] ??
        nameI18n['en'] ??
        nameI18n.values.firstOrNull ??
        key;
  }

  String descriptionFor(String languageCode) {
    return descriptionI18n[languageCode] ??
        descriptionI18n['en'] ??
        descriptionI18n.values.firstOrNull ??
        '';
  }

  Map<String, dynamic> toUpsertJson() => {
        'key': key,
        'name_i18n': nameI18n,
        'description_i18n': descriptionI18n,
        if (icon != null) 'icon': icon,
        'base_price': basePrice,
        'sort_order': sortOrder,
        'requires_car': requiresCar,
        'is_active': isActive,
      };
}

double _toDouble(Object? v) {
  if (v == null) return 0;
  if (v is num) return v.toDouble();
  return double.tryParse(v.toString()) ?? 0;
}

extension<E> on Iterable<E> {
  E? get firstOrNull => isEmpty ? null : first;
}
