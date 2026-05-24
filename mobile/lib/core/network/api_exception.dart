/// Wraps an error returned by the PUTZFEE backend so the UI layer can show a
/// user-friendly message without dealing with [DioException] directly.
class ApiException implements Exception {
  ApiException({required this.message, this.statusCode, this.data});

  final String message;
  final int? statusCode;
  final Object? data;

  bool get isUnauthorized => statusCode == 401;
  bool get isForbidden => statusCode == 403;
  bool get isRateLimited => statusCode == 429;
  bool get isConflict => statusCode == 409;

  @override
  String toString() => 'ApiException($statusCode): $message';
}
