class SlotStatus {
  static const proposed = 'PROPOSED';
  static const confirmed = 'CONFIRMED';
  static const rejected = 'REJECTED';
}

class SlotModel {
  const SlotModel({
    required this.id,
    required this.requestId,
    required this.startAt,
    required this.endAt,
    required this.status,
    required this.createdAt,
  });

  factory SlotModel.fromJson(Map<String, dynamic> json) => SlotModel(
        id: (json['id'] as num).toInt(),
        requestId: (json['request_id'] as num).toInt(),
        startAt: DateTime.parse(json['start_at'].toString()).toLocal(),
        endAt: DateTime.parse(json['end_at'].toString()).toLocal(),
        status: json['status'] as String,
        createdAt: DateTime.parse(json['created_at'].toString()).toLocal(),
      );

  final int id;
  final int requestId;
  final DateTime startAt;
  final DateTime endAt;
  final String status;
  final DateTime createdAt;

  bool get isProposed => status == SlotStatus.proposed;
  bool get isConfirmed => status == SlotStatus.confirmed;
}
