// SPDX-License-Identifier: GPL-3.0-or-later

// UI only: no business logic, no crypto and no secrets in Dart (CLAUDE.md,
// section 6). The bridge to the Rust core arrives with E6.

import 'package:flutter/material.dart';

import 'l10n/app_localizations.dart';

void main() {
  runApp(const RigelApp());
}

class RigelApp extends StatelessWidget {
  const RigelApp({super.key, this.locale});

  /// Forces a locale (tests); `null` follows the system language.
  final Locale? locale;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      onGenerateTitle: (context) => AppLocalizations.of(context).appTitle,
      locale: locale,
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      theme: ThemeData(colorSchemeSeed: Colors.indigo),
      darkTheme: ThemeData(
        colorSchemeSeed: Colors.indigo,
        brightness: Brightness.dark,
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatelessWidget {
  const HomePage({super.key});

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(l10n.appTitle)),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(l10n.foundationNotice, textAlign: TextAlign.center),
              const SizedBox(height: 16),
              Text(l10n.offlineNotice, textAlign: TextAlign.center),
            ],
          ),
        ),
      ),
    );
  }
}
