# dynamicflow

Linux-VM-Profile und eine Go-CLI für lokale Konfiguration, signierte Releases
und Instanzzustände. SSH, VPN und Browser-Toolkits liegen im selben Repository.

In Entwicklung. Entfernte Lifecycle-, Enrollment- und Serving-Aktionen bleiben
mit `control_route_unavailable` gesperrt, bis ihre verifizierte Control-Route
vollständig ist. `examstation` fehlt; `decepticon` ist eine externe Integration.
Das Browser-Toolkit bleibt mit seiner abgelaufenen Sicherheitsfreigabe gesperrt.

## Ausprobieren

Linux, Git, Bash, GNU Make, OpenSSH und Go gemäß [go.mod](go.mod) bereitstellen.
Der erste Build kann Module herunterladen.

Das Repository im eigenen Home-Verzeichnis klonen und die Befehle aus dessen
Wurzelverzeichnis ausführen:

```sh
git clone https://github.com/panzaknacker/dynamicflow.git "$HOME/dynamicflow"
cd "$HOME/dynamicflow"
make demo
make check
```

Die Demo verwendet temporären Zustand und benötigt keine VM oder Cloud.
`make check` baut die CLI und prüft Tests, Race-Detector, vet und statische Regeln.
Für Race-Tests ist ein C-Compiler nötig. VNC-Tests verlangen einen Checkout ohne
gruppen- oder weltweit beschreibbare Elternverzeichnisse; `/tmp` ist ungeeignet.
Die internen Toolkits werden separat mit `make component-static` geprüft.

## Code

- [CLI](internal/cli/) und [Control-Sperre](internal/cli/control_route_gate.go)
- [Release-Prüfung und Veröffentlichung](internal/release/)
- [Signaturen](internal/signing/) und [Reconcile](internal/reconcile/)
- [Profile](profiles/) und [Serving](serving/)

Lokale Tests qualifizieren keinen vollständigen VM-Betrieb. GitHub Actions sind
derzeit deaktiviert; die bisherigen Starts endeten vor dem ersten Job.

## Sicherheit

`FLOW_HOME` enthält Schlüssel, Trust-Pins und Auditdaten und gehört nicht in Git.
SSH-Hostkeys unabhängig prüfen; VNC bleibt auf Loopback. Nur eigene, entbehrliche
VMs verwenden. Sensible Befunde über die private Meldung im GitHub-Security-Tab
teilen, ohne Schlüssel oder echte Inventare in öffentlichen Issues.

[Apache License 2.0](LICENSE).
