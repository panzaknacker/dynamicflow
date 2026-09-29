# Lokale Demo

Die Demo führt den lokalen Go-Kern aus. Sie verwendet temporären State und
Schlüssel; Zielhosts, VMs und Cloud-Konten werden nicht benötigt.

## Voraussetzungen

Linux, Bash, GNU Make, Go gemäß `go.mod` und OpenSSH (`ssh`, `ssh-keygen`).
Der erste Build kann die in `go.mod` und `go.sum` festgelegten Module laden.
Mit vorbereitetem Cache verhindert `GOPROXY=off` weitere Downloads.

## Start

Aus der Repository-Wurzel:

```sh
make demo
```

Alternativ: `./scripts/portfolio-demo.sh`. Mit `make demo GO=/pfad/zu/go`
lässt sich eine bestimmte Go-Installation verwenden. Der Runner ignoriert
übergeordnete `go.work`-Dateien und lädt keine Toolchain nach.

## Ablauf

| Schritt | Prüfung |
| --- | --- |
| Build | `make build` erzeugt die CLI; `flow --version` zeigt den Stand. |
| State | `flow init` und `flow doctor` prüfen getrennte Schlüssel, Werkzeuge und Profile. |
| Profile | `flow profile list` und `flow profile show pbp` zeigen Verfügbarkeit und Abhängigkeiten. |
| Signaturen | `TestCanonicalSignatureBindsDomainAndValue` akzeptiert gültige Daten und lehnt Manipulation, falsche Domäne und falschen Schlüssel ab. |
| Remote-Sperre | `flow --json instance status demo-node` muss mit `control_route_unavailable` und Exitcode 6 abbrechen. |

Ein anderes Ergebnis im letzten Schritt lässt die Demo scheitern. Bei Erfolg
endet die Ausgabe mit `Demo passed`. Die
[Beispielausgabe vom 19.09.](demo-output.txt) enthält normalisierte lokale
Pfade und öffentliche Schlüssel-IDs.

Der Runner entfernt seinen temporären State auch bei Fehlern. Private
Schlüsselinhalte werden nicht ausgegeben. Nur `.flow/bin/flow` bleibt als
ignoriertes Build-Artefakt liegen.

## Fehlerhilfe

- `Missing prerequisite`: Das genannte Werkzeug muss im `PATH` liegen.
- Fehlende Module im Offline-Modus: Abhängigkeiten einmal mit erlaubtem
  Netzwerkzugriff vorbereiten; die festgelegten Versionen beibehalten.
- `doctor_failed`: Einzelprüfungen lesen, besonders OpenSSH und Dateirechte.
  Nicht mit `sudo` auf bestehendem Benutzer-State wiederholen.
- `control_route_unavailable`: Im letzten Demo-Schritt erwartet. Die
  Control-Route ist noch nicht fertig; die Sperre nicht umgehen.

## Weiter prüfen

`make check` ergänzt alle Go-Pakete, Race-Tests, `go vet` und statische
Sicherheitsprüfungen. Dafür wird ein C-Compiler benötigt.
[Ergebnisse und Prüfgrenzen](VERIFICATION.md).

Die vollständige Plattform und externe Integrationen haben eigene
[Abnahmekriterien](COMPLETION-AUDIT.md).
