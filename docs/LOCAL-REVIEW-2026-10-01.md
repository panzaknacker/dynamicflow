# Lokale Nachprüfung · 01.10.2026

`make check demo` bestand mit Go 1.26.8: Build, 32 Unit-Testpakete, dieselben
Pakete mit Race-Detector, vet, statische Prüfungen und fünf Demo-Schritte.
Go-Code und Tests wurden nicht geändert.

[Vollständiges Protokoll](verification/2026-10-01-core-go1.26.8.txt).

Der erste Lauf in der Agent-Sandbox scheiterte an gesperrten Loopback-Sockets
und abweichend dargestellten Eigentümern von Root-Verzeichnissen. Derselbe
Quellstand bestand außerhalb der Sandbox in einem Checkout mit sicheren Pfaden.

## Umgebung und Quellstand

Fedora 44 x86_64, Kernel 7.2.5-200.fc44; Go 1.26.8, soweit verwendet,
und Python 3.14.7. Vorbereitete Werkzeuge und Modulcaches wurden wiederverwendet.
Go-Proxy und Prüfsummenabrufe waren deaktiviert. Daten und Schlüssel waren
synthetisch und temporär.

[Kontext](verification/2026-10-01-context.json) ·
[Geprüfte Code-/Build-Eingaben](verification/2026-10-01-inputs.sha256)

Lokale Checkout-/Werkzeugpfade und zufällige öffentliche Demo-Key-IDs wurden
normalisiert; Ergebnisse und Fehler blieben erhalten. Gitleaks 8.30.1 meldete
bei der Prüfung aller vorhandenen Git-Refs keine Geheimnisse. Nicht mitgelieferte
ursprüngliche Entwicklungshistorie und Produktionsreife sind davon nicht erfasst.

[Gehostete CI-Startfehler](HOSTED-CI.md) sind von diesen lokalen Ergebnissen getrennt.
