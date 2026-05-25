/// Order status constants matching the backend `ORDER_STATUSES`.
class OrderStatus {
  static const pendingReview = 'PENDING_REVIEW';
  static const awaitingUserConfirm = 'AWAITING_USER_CONFIRM';
  static const timeConfirmed = 'TIME_CONFIRMED';
  static const priceConfirmed = 'PRICE_CONFIRMED';
  static const inProgress = 'IN_PROGRESS';
  static const completed = 'COMPLETED';
  static const cancelled = 'CANCELLED';

  static const active = <String>[
    pendingReview,
    awaitingUserConfirm,
    timeConfirmed,
    priceConfirmed,
    inProgress,
  ];

  static const terminal = <String>[completed, cancelled];
}

class OrderModel {
  const OrderModel({
    required this.id,
    required this.userId,
    required this.status,
    required this.serviceKeys,
    required this.createdAt,
    required this.updatedAt,
    this.carId,
    this.latitude,
    this.longitude,
    this.addressText,
    this.notes,
    this.totalPrice,
    this.execDurationMinutes,
    this.paymentType = 'cash',
    this.promotionId,
    this.cancelReason,
    this.startedAt,
    this.finishedAt,
  });

  factory OrderModel.fromJson(Map<String, dynamic> json) => OrderModel(
        id: (json['id'] as num).toInt(),
        userId: (json['user_id'] as num).toInt(),
        status: json['status'] as String,
        serviceKeys: (json['service_keys'] as List? ?? const [])
            .map((e) => e.toString())
            .toList(),
        carId: (json['car_id'] as num?)?.toInt(),
        latitude: _toNullableDouble(json['latitude']),
        longitude: _toNullableDouble(json['longitude']),
        addressText: json['address_text'] as String?,
        notes: json['notes'] as String?,
        totalPrice: _toNullableDouble(json['total_price']),
        execDurationMinutes: (json['exec_duration_minutes'] as num?)?.toInt(),
        paymentType: (json['payment_type'] as String?) ?? 'cash',
        promotionId: (json['promotion_id'] as num?)?.toInt(),
        cancelReason: json['cancel_reason'] as String?,
        startedAt: _parseDate(json['started_at']),
        finishedAt: _parseDate(json['finished_at']),
        createdAt: _parseDate(json['created_at']) ?? DateTime.now(),
        updatedAt: _parseDate(json['updated_at']) ?? DateTime.now(),
      );

  final int id;
  final int userId;
  final String status;
  final List<String> serviceKeys;
  final int? carId;
  final double? latitude;
  final double? longitude;
  final String? addressText;
  final String? notes;
  final double? totalPrice;
  final int? execDurationMinutes;
  final String paymentType;
  final int? promotionId;
  final String? cancelReason;
  final DateTime? startedAt;
  final DateTime? finishedAt;
  final DateTime createdAt;
  final DateTime updatedAt;

  bool get isActive => OrderStatus.active.contains(status);
  bool get isTerminal => OrderStatus.terminal.contains(status);
  bool get canCancel =>
      status == OrderStatus.pendingReview ||
      status == OrderStatus.awaitingUserConfirm ||
      status == OrderStatus.timeConfirmed;
  bool get canReview => status == OrderStatus.completed;
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
