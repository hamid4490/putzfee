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
  --dart-define=API_BASE_URL=https://putzfee-5o2g.onrender.com \
  --dart-define=MAPBOX_TOKEN=pk.eyJ... \
  --dart-define=SERVER_TIMEZONE=Europe/Berlin
```

> The default `API_BASE_URL` baked into the binary is
> `https://putzfee-5o2g.onrender.com`, so a plain `flutter run` will already
> hit production. Override only if you point at a staging or local server.
> The Render free tier sleeps after ~15 minutes idle; the first request can
> take 30–60 seconds to wake the server up (the app waits up to 60 s).

## Configuration

### API server URL

Set `API_BASE_URL` via `--dart-define` or `dart_defines.json`.

| Environment              | Value                                          |
|--------------------------|------------------------------------------------|
| Production (default)     | `https://putzfee-5o2g.onrender.com`            |
| Android emulator + host  | `http://10.0.2.2:8000` *                       |
| iOS Simulator + host     | `http://localhost:8000`                        |
| Physical device on LAN   | `http://<host-LAN-IP>:8000` *                  |

\* HTTP (cleartext) values require `android:usesCleartextTraffic="true"`
in `android/app/src/main/AndroidManifest.xml` for non-debug builds. The
debug variant already allows cleartext.

### Mapbox (optional)

The map / location picker uses Mapbox raster tiles when a token is set,
otherwise it falls back to OpenStreetMap tiles. Mapbox accounts are free
up to ~50k loads/month.

1. Create a token at https://account.mapbox.com/access-tokens/ (default
   public scopes are fine).
2. Add it to `dart_defines.json` as `MAPBOX_TOKEN`, e.g.
   `"MAPBOX_TOKEN": "pk.eyJ1Ijoi..."`.
3. Rebuild — no extra Android / iOS native setup needed.

### Firebase Cloud Messaging (optional)

Push notifications are gated behind Firebase. The app gracefully
degrades when Firebase is **not** configured (push silently no-ops),
so you can ship without it.

To enable FCM:

1. Create / open a Firebase project at https://console.firebase.google.com/.
2. Add an **Android** app to the project for **both** flavors:
   - `de.putzfee.putzfee` (user)
   - `de.putzfee.putzfee.admin` (admin)
   - SHA-1 / SHA-256 fingerprints are not required for FCM.
3. Download the generated `google-services.json` and place it at
   `mobile/android/app/google-services.json` (one file covers both
   flavors as long as both application IDs are registered in the same
   Firebase project).
4. Enable the Google Services Gradle plugin:
   - In `mobile/android/settings.gradle.kts`, add:
     ```kotlin
     plugins {
         id("com.google.gms.google-services") version "4.4.2" apply false
     }
     ```
   - In `mobile/android/app/build.gradle.kts`, add to the `plugins` block:
     ```kotlin
     id("com.google.gms.google-services")
     ```
5. On the **server**, set:
   - `FCM_PROJECT_ID` — your Firebase project ID
   - `GOOGLE_APPLICATION_CREDENTIALS_JSON_B64` — base64 of a
     service-account JSON with the `Firebase Cloud Messaging API` role
6. Rebuild the app: `flutter clean && flutter run …`.

For iOS, in addition to `GoogleService-Info.plist`, you need APNs auth
key configuration in the Firebase console.

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
