# Beiträge

Mit [Entwicklungsleitfaden](docs/DEVELOPMENT.md) und [PROJECT_STATUS.md](PROJECT_STATUS.md) beginnen.
Änderungen fokussiert halten und Problem, Verhalten sowie betroffene
Vertrauensgrenzen erläutern.

## Lokale Prüfung

Bei Änderungen am Go-Kern `make check` und für den lokalen Einstieg `make demo`
ausführen. Linux, Go gemäß `go.mod`, GNU Make, Bash, OpenSSH und C-Compiler
bereitstellen. VNC-Prüfungen brauchen sichere übergeordnete Checkout-Verzeichnisse.

Tatsächlich ausgeführte Befehle, Umgebung, Ergebnisse und übersprungene Checks
festhalten. Geänderte Go-Dateien mit `gofmt` formatieren. Verhaltensänderungen
brauchen gezielte Regressionen für Fehlerfälle und abgelehnte Eingaben.

## Anforderungen an Beiträge

Ausdrückliche Freigaben, geprüftes Vertrauen, Fehlerbehandlung und Recovery-Grenzen
erhalten. Ändert sich eine Fähigkeit oder ihre Abnahme, den Projektstatus anpassen.
Lokale, simulierte und echte Betriebsnachweise getrennt benennen.

Synthetische Fixtures verwenden. Keine Binaries, privaten Zustände, Zugangsdaten,
echten Inventare oder Fremdquellen ohne Lizenzhinweise committen.
Sensible Befunde über [SECURITY.md](SECURITY.md) melden.

## Quellbedingungen

Für Beiträge gilt die bestehende [Apache-2.0-Lizenz](LICENSE).
