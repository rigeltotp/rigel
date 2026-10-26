# Rigel app

The Flutter UI for Android, iOS/iPadOS, macOS, Windows and Linux. It contains
no business logic and no cryptography; everything security-relevant lives in
the Rust core in `../core` (see `../CLAUDE.md`).

```sh
flutter pub get
dart format --output=none --set-exit-if-changed .
flutter analyze
flutter test
```
