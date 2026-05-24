/// Tokens + minimal user info returned by `/auth/login`, `/auth/register`,
/// `/auth/refresh`.
class TokenPair {
  TokenPair({
    required this.accessToken,
    required this.refreshToken,
    required this.userId,
    required this.isAdmin,
  });

  factory TokenPair.fromJson(Map<String, dynamic> json) => TokenPair(
        accessToken: json['access_token'] as String,
        refreshToken: json['refresh_token'] as String,
        userId: (json['user_id'] as num).toInt(),
        isAdmin: (json['is_admin'] as bool?) ?? false,
      );

  final String accessToken;
  final String refreshToken;
  final int userId;
  final bool isAdmin;
}

class AppUser {
  AppUser({
    required this.id,
    required this.phone,
    required this.fullName,
    this.address,
    this.photoUrl,
    this.locale = 'en',
    this.isAdmin = false,
  });

  factory AppUser.fromJson(Map<String, dynamic> json) => AppUser(
        id: (json['id'] as num).toInt(),
        phone: json['phone'] as String,
        fullName: json['full_name'] as String,
        address: json['address'] as String?,
        photoUrl: json['photo_url'] as String?,
        locale: (json['locale'] as String?) ?? 'en',
        isAdmin: (json['is_admin'] as bool?) ?? false,
      );

  final int id;
  final String phone;
  final String fullName;
  final String? address;
  final String? photoUrl;
  final String locale;
  final bool isAdmin;
}
