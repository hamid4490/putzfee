class NotificationModel {
  const NotificationModel({
    required this.id,
    required this.title,
    required this.createdAt,
    this.body,
    this.payload,
    this.readAt,
  });

  factory NotificationModel.fromJson(Map<String, dynamic> json) =>
      NotificationModel(
        id: (json['id'] as num).toInt(),
        title: json['title'] as String,
        body: json['body'] as String?,
        payload: (json['payload'] as Map?)?.cast<String, dynamic>(),
        readAt: _parseDate(json['read_at']),
        createdAt: _parseDate(json['created_at']) ?? DateTime.now(),
      );

  final int id;
  final String title;
  final String? body;
  final Map<String, dynamic>? payload;
  final DateTime? readAt;
  final DateTime createdAt;

  bool get isUnread => readAt == null;
}

DateTime? _parseDate(Object? raw) {
  if (raw == null) return null;
  return DateTime.tryParse(raw.toString())?.toLocal();
}
