# Dynamicflow

Dynamicflow ist ein Go/Linux-Projekt für wiederverwendbare VM-Umgebungen.
Es verbindet lokale Konfiguration, signierte Releases und nachvollziehbare
Zustandsänderungen. Der Ausgangspunkt sind eigene Research-Umgebungen, die
bei unterschiedlichen Hosting-Anbietern vorbereitet und erneut genutzt werden.

`flow` bietet eine textbasierte Terminaloberfläche (TUI), einzelne Befehle
(CLI) und maschinenlesbare JSON-Ausgaben. Diese Oberflächen verwenden dieselben
Application Services: Die Bedienung verändert nicht die fachlichen Regeln.

## Aktueller Umfang

Lokal verfügbar sind Systeminitialisierung und Systemauswahl, Diagnosen,
Profilübersichten sowie Release-Prüfung und ausdrücklich lokale Veröffentlichung.
Befehle können an die erwartete System-ID gebunden werden, damit eine zwischenzeitlich
geänderte Auswahl nicht unbemerkt das falsche System betrifft.

Entfernte Lifecycle-, Enrollment- und Serving-Aktionen bleiben mit
`control_route_unavailable` gesperrt, solange die verifizierte Route über den Zugriffsknoten (Control)
nicht vollständig ist. Das ist ein Entwicklungsstand, keine Produktionsfreigabe.
`examstation` wird nicht mitgeliefert. `decepticon` beschreibt eine externe
Integration ohne mitgelieferte Toolquellen und ist nicht installierbar.
Das Browser-Toolkit bleibt für normale Releases gesperrt.

## Ausprobieren

Benötigt werden Linux, Git, Bash, GNU Make, OpenSSH und Go gemäß
[go.mod](go.mod). Der erste Build kann Module herunterladen; Race-Tests brauchen
einen C-Compiler. Das Repository lokal klonen und im Wurzelverzeichnis ausführen:

```sh
git clone https://github.com/panzaknacker/dynamicflow.git "$HOME/dynamicflow"
cd "$HOME/dynamicflow"
make demo
make check
```

Die Demo verwendet temporären Zustand und benötigt keine VM oder Cloud.
`make check` ist das lokale Build- und Prüfgate; es ersetzt keine Real-VM-Abnahme.
VNC-Tests benötigen sichere Elternverzeichnisse: Ein Checkout unter `/tmp`
ist dafür ungeeignet. GitHub Actions sind derzeit deaktiviert.

## Code

- [CLI](internal/cli/), [gemeinsame Services](internal/application/) und [TUI](internal/tui/)
- [Release-Prüfung](internal/release/), [Signaturen](internal/signing/) und [Zustandsabgleich](internal/reconcile/)
- [Profile](profiles/) und [Architekturübersicht](docs/ARCHITEKTUR.md)

Private Schlüssel, Trust-Pins und Auditdaten in `FLOW_HOME` bleiben lokal und
gehören nicht in Git. Für praktische Versuche nur eigene, entbehrliche VMs
verwenden. [Apache License 2.0](LICENSE); Drittanbieterhinweise bleiben erhalten.
