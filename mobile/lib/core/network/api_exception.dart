/// Categorises a network-layer failure so the UI can show a localised
/// message without inspecting Dio internals.
enum ApiErrorCode {
  /// HTTP error returned by the server (4xx / 5xx).
  http,

  /// Connection could not be established (DNS, host unreachable, …).
  noConnection,

  /// Timeout while connecting or waiting for the response.
  timeout,

  /// Request was cancelled by the caller.
  cancelled,

  /// TLS / certificate validation failure.
  badCertificate,

  /// Anything else.
  unknown,
}

/// Wraps an error returned by the PUTZFEE backend so the UI layer can show a
/// user-friendly message without dealing with [DioException] directly.
class ApiException implements Exception {
  ApiException({
    required this.message,
    this.statusCode,
    this.data,
    this.code = ApiErrorCode.unknown,
  });

  final String message;
  final int? statusCode;
  final Object? data;
  final ApiErrorCode code;

  bool get isUnauthorized => statusCode == 401;
  bool get isForbidden => statusCode == 403;
  bool get isRateLimited => statusCode == 429;
  bool get isConflict => statusCode == 409;

  /// `true` when the failure happened before reaching the server
  /// (i.e. likely a connectivity / DNS / timeout issue).
  bool get isNetworkFailure =>
      code == ApiErrorCode.noConnection ||
      code == ApiErrorCode.timeout ||
      code == ApiErrorCode.badCertificate;

  @override
  String toString() => message;
}
