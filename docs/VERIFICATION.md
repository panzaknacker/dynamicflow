# Lokaler Prüfstand

## 21.09.2026

Arch Linux x86_64, Kernel 7.2.5-hardened1-1-hardened, Go 1.24.2 und 1.26.8,
GCC 16.2.1. Die Läufe verwendeten temporäre Quellkopien und vorbereitete Module.
`GOPROXY=off`, `GOSUMDB=off` und `GOTOOLCHAIN=local` verhinderten Downloads.
[Geprüfte Code- und Builddateien](verification/2026-09-21-inputs.sha256).

| Prüfung | Ergebnis | Protokoll |
| --- | --- | --- |
| `make demo`, Go 1.24.2 | Fünf Schritte bestanden | [Demo](verification/2026-09-21-demo-go1.24.2.txt) |
| `make demo`, Go 1.26.8 | Fünf Schritte bestanden | [Demo](verification/2026-09-21-demo-go1.26.8.txt) |
| `make check`, Go 1.24.2 | Build, 32 Testpakete normal und mit Race-Detector, vet und statische Prüfungen bestanden | [Kerncheck](verification/2026-09-21-core-go1.24.2.txt) |
| `make check`, Go 1.26.8 | Derselbe vollständige Kerncheck bestanden | [Kerncheck](verification/2026-09-21-core-go1.26.8.txt) |

Der erste Versuch unter `/tmp` scheiterte an der bestehenden VNC-Pfadprüfung:
Sie lehnt gruppen- oder weltweit beschreibbare übergeordnete Verzeichnisse ab.
Die Wiederholung lief mit unverändertem Code in einer privaten Projektkopie.
[Erster Lauf, Go 1.24.2](verification/2026-09-21-tmp-path-go1.24.2.txt),
[Go 1.26.8](verification/2026-09-21-tmp-path-go1.26.8.txt).

## Übernommene Korrektur

Beim abschließenden Review am selben Tag bestanden auch ShellCheck 0.11.0 für
`scripts/portfolio-demo.sh` und die beiden CLI-Route-Gate-Tests mit Go 1.26.8.
[ShellCheck](verification/2026-09-21-followup-shellcheck.txt),
[Route-Gates](verification/2026-09-21-followup-route-gate.txt).
Das [Threat Model](THREAT-MODEL.md) unterscheidet jetzt lokale Funktionen,
gesperrte Remote-Aktionen und Anforderungen an die Zielarchitektur.

Der Binary-Regressionstest verwendet nun wie der normale Build
`-buildvcs=false`. So hängt ein Quellarchiv nicht von fremden Git-Metadaten
seines Elternverzeichnisses ab. Die Prüfung der erzeugten Binary bleibt erhalten.
Demo und Testkommentar wurden an das bestehende Codeprofil angepasst.

## Frühere Prüfung vom 19.09.2026

Der separate ZIP-Arbeitsstand bestand die Demo und denselben Go-Kerncheck mit
beiden Versionen. Die damaligen
[Go-1.24.2-](verification/core-go1.24.2.txt) und
[Go-1.26.8-Protokolle](verification/core-go1.26.8.txt),
[Dateiliste](verification/source-manifest.sha256) und
[Secret-Scan-Ausgabe](verification/secret-scan.txt) bleiben als historische Belege.

## Einordnung

Die Protokolle ersetzen nur lokale Pfade und zufällige öffentliche Demo-Key-IDs.
Testergebnisse und Fehler bleiben unverändert. Die ursprüngliche
Entwicklungshistorie wurde nicht mitgeliefert; das private Repository beginnt
mit dem geprüften Snapshot.

GitHub Actions bleiben deaktiviert. Gehostete CI, vollständiger Plattform-Release,
Control-Route, Vier-VM-Abnahme und PBP-Soak sind nicht durch diese Läufe belegt.
[Offene Arbeiten](../PROJECT_STATUS.md).

## Quellprüfung

Gitleaks 8.30.1 meldete am 21.09.2026 im sauberen Quell-Export keine Funde.
[Scanner-Ausgabe](verification/2026-09-21-source-scan.txt). Lokale Links und
Dateihygiene bestanden; die Git-Historie ist eine separate Prüfung.
