import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../config/app_config.dart';
import '../storage/token_storage.dart';
import 'api_exception.dart';

/// How long Dio waits for a TCP connection. The Render free tier can take
/// 30-60 s to wake up from sleep, so we keep this generous on the first hit.
const Duration _kConnectTimeout = Duration(seconds: 60);
const Duration _kReceiveTimeout = Duration(seconds: 60);
const Duration _kSendTimeout = Duration(seconds: 60);

/// Thin Dio wrapper that:
/// * attaches the bearer access token
/// * transparently refreshes on 401
/// * sets `Accept-Language`
/// * normalises errors to [ApiException]
class ApiClient {
  ApiClient({required TokenStorage storage}) : _storage = storage {
    _dio = Dio(
      BaseOptions(
        baseUrl: AppConfig.apiBaseUrl,
        connectTimeout: _kConnectTimeout,
        receiveTimeout: _kReceiveTimeout,
        sendTimeout: _kSendTimeout,
        headers: {
          HttpHeaders.contentTypeHeader: 'application/json',
        },
      ),
    );
    _dio.interceptors.add(_authInterceptor());
    if (AppConfig.isDebug) {
      _dio.interceptors.add(LogInterceptor(
        request: false,
        requestHeader: false,
        requestBody: false,
        responseHeader: false,
        responseBody: false,
        error: true,
        logPrint: (o) => debugPrint('$o'),
      ));
    }
  }

  final TokenStorage _storage;
  late final Dio _dio;
  String _languageCode = 'en';
  bool _refreshing = false;

  Dio get raw => _dio;

  set languageCode(String code) => _languageCode = code;

  InterceptorsWrapper _authInterceptor() {
    return InterceptorsWrapper(
      onRequest: (options, handler) async {
        options.headers['Accept-Language'] = _languageCode;
        final access = await _storage.readAccess();
        if (access != null && access.isNotEmpty) {
          options.headers[HttpHeaders.authorizationHeader] = 'Bearer $access';
        }
        handler.next(options);
      },
      onError: (err, handler) async {
        final shouldRetry = err.response?.statusCode == 401 &&
            err.requestOptions.path != '/auth/refresh' &&
            !_refreshing;
        if (!shouldRetry) {
          handler.next(err);
          return;
        }
        try {
          _refreshing = true;
          final ok = await _refreshOnce();
          if (!ok) {
            handler.next(err);
            return;
          }
          final newAccess = await _storage.readAccess();
          final req = err.requestOptions;
          req.headers[HttpHeaders.authorizationHeader] = 'Bearer $newAccess';
          final response = await _dio.fetch<dynamic>(req);
          handler.resolve(response);
        } catch (_) {
          handler.next(err);
        } finally {
          _refreshing = false;
        }
      },
    );
  }

  Future<bool> _refreshOnce() async {
    final refresh = await _storage.readRefresh();
    if (refresh == null || refresh.isEmpty) return false;
    try {
      final r = await _dio.post<Map<String, dynamic>>(
        '/auth/refresh',
        data: {'refresh_token': refresh},
      );
      final data = r.data;
      if (data == null) return false;
      await _storage.updateTokens(
        accessToken: data['access_token'] as String,
        refreshToken: data['refresh_token'] as String,
      );
      return true;
    } catch (_) {
      await _storage.clear();
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // Convenience wrappers that surface [ApiException] instead of [DioException]
  // -------------------------------------------------------------------------

  Future<T> get<T>(String path,
      {Map<String, dynamic>? query, Options? options}) async {
    return _run(() => _dio.get<T>(path,
        queryParameters: query, options: options));
  }

  Future<T> post<T>(String path,
      {Object? body, Map<String, dynamic>? query, Options? options}) async {
    return _run(() => _dio.post<T>(path,
        data: body, queryParameters: query, options: options));
  }

  Future<T> patch<T>(String path, {Object? body, Options? options}) async {
    return _run(() => _dio.patch<T>(path, data: body, options: options));
  }

  Future<T> delete<T>(String path, {Object? body, Options? options}) async {
    return _run(() => _dio.delete<T>(path, data: body, options: options));
  }

  Future<T> _run<T>(Future<Response<T>> Function() exec) async {
    try {
      final r = await exec();
      return r.data as T;
    } on DioException catch (e) {
      throw _convert(e);
    }
  }

  ApiException _convert(DioException e) {
    final data = e.response?.data;
    final code = _categorise(e);
    String message;
    if (data is Map && data['detail'] is String) {
      message = data['detail'] as String;
    } else if (data is Map && data['message'] is String) {
      message = data['message'] as String;
    } else {
      message = switch (code) {
        ApiErrorCode.timeout =>
          'Could not reach the server. Please check your connection and try again.',
        ApiErrorCode.noConnection =>
          'No internet connection. Please check your network and try again.',
        ApiErrorCode.badCertificate =>
          'Secure connection failed. Please try again later.',
        ApiErrorCode.cancelled => 'Request cancelled.',
        ApiErrorCode.http || ApiErrorCode.unknown =>
          e.message ?? 'Something went wrong. Please try again.',
      };
    }
    return ApiException(
      message: message,
      statusCode: e.response?.statusCode,
      data: data,
      code: code,
    );
  }

  ApiErrorCode _categorise(DioException e) {
    switch (e.type) {
      case DioExceptionType.connectionTimeout:
      case DioExceptionType.sendTimeout:
      case DioExceptionType.receiveTimeout:
        return ApiErrorCode.timeout;
      case DioExceptionType.connectionError:
        return ApiErrorCode.noConnection;
      case DioExceptionType.badCertificate:
        return ApiErrorCode.badCertificate;
      case DioExceptionType.cancel:
        return ApiErrorCode.cancelled;
      case DioExceptionType.badResponse:
        return ApiErrorCode.http;
      case DioExceptionType.unknown:
        final err = e.error;
        if (err is SocketException) return ApiErrorCode.noConnection;
        return ApiErrorCode.unknown;
    }
  }
}

final apiClientProvider = Provider<ApiClient>((ref) {
  final storage = ref.watch(tokenStorageProvider);
  return ApiClient(storage: storage);
});
