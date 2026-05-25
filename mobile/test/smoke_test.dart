import 'package:flutter_test/flutter_test.dart';

import 'package:putzfee/features/auth/data/auth_models.dart';

void main() {
  test('TokenPair.fromJson parses canonical response', () {
    final tp = TokenPair.fromJson({
      'access_token': 'a',
      'refresh_token': 'r',
      'user_id': 7,
      'is_admin': true,
      'token_type': 'Bearer',
    });
    expect(tp.accessToken, 'a');
    expect(tp.refreshToken, 'r');
    expect(tp.userId, 7);
    expect(tp.isAdmin, isTrue);
  });

  test('AppUser.fromJson tolerates missing optional fields', () {
    final u = AppUser.fromJson({
      'id': 1,
      'phone': '+491230000000',
      'full_name': 'Mina',
    });
    expect(u.id, 1);
    expect(u.phone, '+491230000000');
    expect(u.fullName, 'Mina');
    expect(u.isAdmin, isFalse);
    expect(u.locale, 'en');
  });
}
