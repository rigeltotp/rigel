// SPDX-License-Identifier: GPL-3.0-or-later

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rigel/main.dart';

void main() {
  testWidgets('shows the English start screen', (tester) async {
    await tester.pumpWidget(const RigelApp(locale: Locale('en')));
    await tester.pumpAndSettle();

    expect(find.text('Rigel'), findsOneWidget);
    expect(find.textContaining('completely offline'), findsOneWidget);
  });

  testWidgets('shows the German start screen', (tester) async {
    await tester.pumpWidget(const RigelApp(locale: Locale('de')));
    await tester.pumpAndSettle();

    expect(find.textContaining('vollständig offline'), findsOneWidget);
  });
}
