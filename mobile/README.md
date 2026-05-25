# PUTZFEE — Mobile (Flutter)

The companion Android app for the PUTZFEE booking API.

## Stack

- Flutter 3.5+ / Dart 3
- Material 3 + Google Fonts (Inter)
- Riverpod for state, Dio for HTTP, GoRouter for navigation
- `flutter_secure_storage` for tokens, `shared_preferences` for locale/theme
- JSON-driven i18n in `assets/i18n/{en,fa,de}.json`

## Layout

```
lib/
├── main.dart            # user flavor entry point
├── main_admin.dart      # admin flavor entry point
├── core/
│   ├── config/        # compile-time settings (API base url, mapbox token)
│   ├── localization/  # AppLocalizations + locale provider
│   ├── network/       # Dio client + ApiException + auto refresh
│   ├── routing/       # GoRouter + auth gate
│   ├── storage/       # secure-storage token store
│   └── theme/         # Material 3 light/dark + ThemeMode provider
└── features/
    ├── auth/          # login, register, splash, auth controller
    ├── home/          # user main + admin main bottom navs
    ├── orders/        # user order history
    ├── ai_assistant/  # in-app AI chat
    ├── profile/       # profile, language, theme, sign-out
    └── (cars, services, promotions, scheduling, notifications, map, reviews — to come)
```

## Quickstart

```bash
cd mobile
flutter pub get

# Copy the example defines file and fill in your values
cp dart_defines.json.example dart_defines.json

# Run the admin flavor
flutter run --flavor admin -t lib/main_admin.dart \
  --dart-define-from-file=dart_defines.json

# Run the user (default) flavor
flutter run --flavor user -t lib/main.dart \
  --dart-define-from-file=dart_defines.json

# Or pass dart-defines inline instead of using a file
flutter run --flavor user \
  --dart-define=API_BASE_URL=http://10.0.2.2:8000 \
  --dart-define=MAPBOX_TOKEN=pk.eyJ... \
  --dart-define=SERVER_TIMEZONE=Europe/Berlin
```

### Build flavors

| Flavor  | Entry point          | Application ID              |
|---------|----------------------|-----------------------------|
| `admin` | `lib/main_admin.dart`| `de.putzfee.putzfee.admin`  |
| `user`  | `lib/main.dart`      | `de.putzfee.putzfee`        |

Both flavors share the same codebase; admin vs. user routing is decided
at login time by the backend (`is_admin` flag).

## What's wired up

- Multi-language UI (en / fa / de) with persisted locale.
- Dark / light / system theme switcher.
- JWT login + register against `/auth/*`, with **transparent refresh** on 401.
- Routing gated on auth status, with admin / user separation.
- User home pulls `/public/home` (services + active promotions) with pull-to-refresh.
- User orders pulls `/orders` with empty + error states.
- Admin dashboard pulls `/admin/orders` (recent orders) with empty + error states.
- AI chat against `/ai/chat`.
- Profile screen: avatar, name, phone, language, theme, sign-out.

## What's stubbed for the next PR

- New-order flow (service picker, car, address, location pin)
- Mapbox map view
- Scheduling propose / confirm UI
- Admin service / promotion CRUD
- FCM push notifications + local notifications
- Image upload (image_picker + flutter_image_compress)

## Backend timezone

Server uses `Europe/Berlin` (`SERVER_TIMEZONE`). The app stores nothing about
times locally — it displays whatever the backend returns, converted to the
device's locale. Keep client and server timezones aligned in deployment.
