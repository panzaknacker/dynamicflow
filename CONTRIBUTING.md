# Beiträge

Mit dem [Entwicklungsleitfaden](docs/DEVELOPMENT.md) und dem
[Projektstatus](PROJECT_STATUS.md) beginnen. Beiträge fokussiert halten und das
beobachtbare Verhalten, die betroffene Sicherheitsgrenze und die ausgeführten
Prüfungen erläutern.

Bei Änderungen am Go-Kern `make check` ausführen. Geänderte Go-Dateien mit
`gofmt` formatieren. Bei Änderungen an Komponentenskripten die passende lokale
Komponentenprüfung ausführen. Änderungen an Signaturen, Vertrauen, Enrollment
oder Dateisystemrechten brauchen gezielte Regressionstests für abgelehnte
Eingaben ebenso wie für den vorgesehenen Weg.

Keine erzeugten Binaries, privaten Zustand, Zugangsdaten, echten Inventare,
Vendor-Archive oder ohne Lizenzhinweise kopierten Fremdquellcode committen.
Synthetische Fixtures verwenden. Sicherheitsprobleme vertraulich melden, wie in
[SECURITY.md](SECURITY.md) beschrieben.

Unfertiges Verhalten in codenahen Meldungen und in der Dokumentation als
**in Entwicklung** gekennzeichnet lassen. Nachweise aus simulierten, lokalen
und echten Umgebungen getrennt beschreiben. Ein grüner Kerntest rechtfertigt
keine Aussage über Produktionsreife.

Beiträge erfolgen unter der Apache-2.0-Lizenz des Repositorys. Bestehende
Urheberrechts- und Drittanbieterhinweise erhalten.
