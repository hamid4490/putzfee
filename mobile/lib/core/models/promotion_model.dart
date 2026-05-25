class PromotionModel {
  const PromotionModel({
    required this.id,
    required this.key,
    required this.titleI18n,
    required this.descriptionI18n,
    this.imageUrl,
    this.discountPercent,
    this.flatDiscount,
    this.minServices,
    this.appliesToKeys,
    this.validFrom,
    this.validTo,
    this.isActive = true,
  });

  factory PromotionModel.fromJson(Map<String, dynamic> json) => PromotionModel(
        id: (json['id'] as num).toInt(),
        key: json['key'] as String,
        titleI18n: _toStringMap(json['title_i18n']),
        descriptionI18n: _toStringMap(json['description_i18n']),
        imageUrl: json['image_url'] as String?,
        discountPercent: _toNullableDouble(json['discount_percent']),
        flatDiscount: _toNullableDouble(json['flat_discount']),
        minServices: (json['min_services'] as num?)?.toInt(),
        appliesToKeys: (json['applies_to_keys'] as List?)
            ?.map((e) => e.toString())
            .toList(),
        validFrom: _parseDate(json['valid_from']),
        validTo: _parseDate(json['valid_to']),
        isActive: (json['is_active'] as bool?) ?? true,
      );

  final int id;
  final String key;
  final Map<String, String> titleI18n;
  final Map<String, String> descriptionI18n;
  final String? imageUrl;
  final double? discountPercent;
  final double? flatDiscount;
  final int? minServices;
  final List<String>? appliesToKeys;
  final DateTime? validFrom;
  final DateTime? validTo;
  final bool isActive;

  String titleFor(String languageCode) =>
      titleI18n[languageCode] ??
      titleI18n['en'] ??
      titleI18n.values.firstOrNull ??
      key;

  String descriptionFor(String languageCode) =>
      descriptionI18n[languageCode] ??
      descriptionI18n['en'] ??
      descriptionI18n.values.firstOrNull ??
      '';

  Map<String, dynamic> toUpsertJson() => {
        'key': key,
        'title_i18n': titleI18n,
        'description_i18n': descriptionI18n,
        if (imageUrl != null) 'image_url': imageUrl,
        if (discountPercent != null) 'discount_percent': discountPercent,
        if (flatDiscount != null) 'flat_discount': flatDiscount,
        if (minServices != null) 'min_services': minServices,
        if (appliesToKeys != null) 'applies_to_keys': appliesToKeys,
        if (validFrom != null) 'valid_from': validFrom!.toUtc().toIso8601String(),
        if (validTo != null) 'valid_to': validTo!.toUtc().toIso8601String(),
        'is_active': isActive,
      };
}

Map<String, String> _toStringMap(Object? raw) {
  if (raw is! Map) return const {};
  return raw.map((k, v) => MapEntry(k.toString(), v?.toString() ?? ''));
}

double? _toNullableDouble(Object? v) {
  if (v == null) return null;
  if (v is num) return v.toDouble();
  return double.tryParse(v.toString());
}

DateTime? _parseDate(Object? raw) {
  if (raw == null) return null;
  return DateTime.tryParse(raw.toString())?.toLocal();
}

extension<E> on Iterable<E> {
  E? get firstOrNull => isEmpty ? null : first;
}
