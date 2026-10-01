# dynamicflow

Wiederverwendbare Linux-VM-Profile für Research und autorisierte Security-Labs.
Die Go-Control-Plane löst Komponentenabhängigkeiten auf, prüft signierte Releases
und verwaltet gewünschte Instanzzustände.

Das Projekt entstand, um ähnliche VM- und Node-Konfigurationen beim Wechsel
von Hosting-Anbietern wiederzuverwenden. Private Varianten habe ich für eigene
Research eingesetzt; ihre genaue Zuordnung zu diesem Snapshot ist noch offen.
[Hintergrund und Entscheidungen](docs/PORTFOLIO.md).

**In Entwicklung.** Der lokale Go-Kern ist zur Evaluierung verfügbar.
Entfernter Lebenszyklus, Enrollment und Serving bleiben mit
`control_route_unavailable` gesperrt, solange die neue Control-Route unvollständig ist.
[Umfang und offene Arbeit](PROJECT_STATUS.md).

## Lokal ausprobieren

Voraussetzungen: Linux, Bash, GNU Make, OpenSSH (`ssh`, `ssh-keygen`) und Go
gemäß [go.mod](go.mod). Der erste Build kann Go-Module herunterladen.

```sh
make demo
```

Die Demo baut die CLI, erzeugt temporären Zustand, zeigt Profile, prüft
Signaturen und bestätigt die erwartete Remote-Sperre. Kein Cloud-Konto oder
bereitgestellte VM erforderlich. [Ablauf und Fehlerhilfe](docs/DEMO.md).

Für die vollständige Kernprüfung zusätzlich einen C-Compiler bereitstellen:

```sh
make check
```

Der Lauf umfasst Build, Unit- und Race-Tests, `go vet` und statische
Sicherheitsprüfungen. VNC-Tests verlangen einen Checkout ohne gruppen- oder
weltweit beschreibbare übergeordnete Verzeichnisse; `/tmp` erfüllt diese Bedingung nicht.

## Code-Einstiege

| Bereich | Code | Entscheidung |
| --- | --- | --- |
| Profile | [Auflösung](internal/cli/profile.go) · [Definitionen](profiles/) | Abhängigkeiten vor einer Änderung auflösen. |
| Signaturen | [Signieren](internal/signing/) · [Release-Prüfung](internal/release/) | Release, Soll-Zustand und Control verwenden getrennte Vertrauenswurzeln. |
| Remote-Grenze | [Control-Sperre](internal/cli/control_route_gate.go) | Unfertige Aktionen vor Zustands-, Netzwerk- oder Prozesszugriff ablehnen. |
| Verteilung | [Serving](serving/) | Verteilung und vollständigen Betrieb getrennt qualifizieren. |

`examstation` ist deklariert, sein Quellcode fehlt. `decepticon` ist eine externe
Integration. Beide bleiben im Target-Runner gesperrt. Komponentenabnahme und
vollständiger Plattform-Release liegen außerhalb von `make check`.

## Nachweise und Grenzen

Die protokollierten September-Läufe bestanden Demo und Kerncheck mit Go 1.24.2
und 1.26.8: 32 Testpakete normal und mit Race-Detector sowie vet und statische
Prüfungen. [Befehle und Umgebung](docs/VERIFICATION.md).
[Aktuelle lokale Nachprüfung](docs/LOCAL-REVIEW-2026-10-01.md).

`FLOW_HOME` enthält private Schlüssel, Trust-Pins und Auditdaten und bleibt
außerhalb von Git. SSH-Hostkeys unabhängig prüfen; `ssh-keyscan` allein stellt
kein Vertrauen her. VNC bleibt auf Loopback. Control-Route, Mehr-VM-Lebenszyklus
und Recovery benötigen weitere Abnahme. [Threat Model](docs/THREAT-MODEL.md).

Die [GitHub-Workflows](https://github.com/panzaknacker/dynamicflow/actions)
sind von lokalen Ergebnissen getrennt. Der aktuelle
[CI-Startfehler](docs/HOSTED-CI.md) ist dokumentiert.

## Dokumentation

- [Demo](docs/DEMO.md) · [Prüfstand](docs/VERIFICATION.md) · [Projektstatus](PROJECT_STATUS.md)
- [Entwicklung](docs/DEVELOPMENT.md) · [Architektur](docs/adr/0001-platform-control-plane.md)
- [Betrieb](docs/OPERATOR-RUNBOOK.md) · [Recovery](docs/RECOVERY-RUNBOOK.md)
- [Abnahmematrix](docs/COMPLETION-AUDIT.md) · [VM-Lab](docs/LAB-E2E-RUNBOOK.md)
- [Beiträge](CONTRIBUTING.md) · [Sicherheitsmeldungen](SECURITY.md)

## Lizenz

[Apache License 2.0](LICENSE). Drittanbieterhinweise bleiben erhalten.
