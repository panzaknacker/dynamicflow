# Projektstatus

- Stand: in Entwicklung; Kandidat für die Veröffentlichung des Quellcodes
- Umfang: lokale Go-Control-Plane, signierter Soll-Zustand und Verteilung von Releases
- Vorgesehene Nutzung: Entwicklung und Wegwerf-Labs
- Produktionssupport: keiner
- Lizenz: Apache-2.0

## Lokale Prüfung: 21.09.2026

`make demo` und der vollständige `make check` bestanden mit Go 1.24.2 und 1.26.8.
Jeder Kernlauf umfasste 32 Testpakete, dieselben Pakete mit Race-Detector, vet
und statische Sicherheitsprüfungen. Die VNC-Tests brauchen einen Checkout ohne
gruppen- oder weltweit beschreibbares übergeordnetes Verzeichnis; die
erfolgreichen Läufe nutzten einen privaten Projektpfad.
[Befehle, Protokolle und frühere Ergebnisse](docs/VERIFICATION.md).

Der normale Build verwendet festgelegte Module und braucht weder einen
Vendor-Baum noch den examstation-Quellcode. `make offline-build` braucht eine
separate Vendor-Vorbereitung. Die mitgelieferten Komponentenprüfungen bleiben
von der Go-Kernprüfung getrennt.

## Offene Arbeit

- Die neue Control-Route fertigstellen. Entfernter Lebenszyklus, Enrollment,
  Serving und Remote-Publish bleiben gesperrt.
- Den Vier-VM-Ablauf und den PBP-Soak qualifizieren.
- Alle Komponenten und Offline-Eingaben für ein vollständiges signiertes
  Plattform-Release vorbereiten.
- Den fehlenden examstation-Quellcode und die externe Decepticon-Integration
  prüfen.
- Gehostete CI sowie echte Deployment- und Recovery-Tests beobachten. GitHub
  Actions bleiben deaktiviert.

Siehe [Entwicklungsleitfaden](docs/DEVELOPMENT.md),
[Abnahmematrix](docs/COMPLETION-AUDIT.md) und [Sicherheitsrichtlinie](SECURITY.md).
