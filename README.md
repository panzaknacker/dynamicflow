# Dynamicflow

Dynamicflow entstand, weil ich für eigene offensive Security Research zwischen
Hosting-Anbietern wechsle und VMs und Nodes nicht jedes Mal neu vorbereiten
wollte. Auch die Kosten waren ein Grund für diese Wechsel. Das Werkzeug bündelt
wiederverwendbare Linux-VM-Profile für Labs und autorisierte Tests.

Die Go-Control-Plane verwaltet Profile, signierte Releases und gewünschte
Instanzzustände. Release-, Desired-State- und Control-Signaturen verwenden
getrennte Schlüssel.
[Hintergrund und Entscheidungen](docs/PORTFOLIO.md).

## Stand dieses Repositorys

**In Entwicklung.** Der lokale Go-Kern lässt sich bauen und testen. Die neue
Control-Route ist unvollständig; entfernte Lifecycle-Aktionen, Enrollment und
Serving-Betrieb sind derzeit mit `control_route_unavailable` gesperrt.

## Lokal ansehen

```sh
make demo
```

Die Demo baut die CLI, legt temporären State an, zeigt Profile und prüft
Signaturen sowie die Remote-Sperre. Benötigt werden Linux, Bash, GNU Make,
Go gemäß `go.mod` und OpenSSH (`ssh`, `ssh-keygen`). Beim ersten Build können
Go-Module geladen werden. [Ablauf und Fehlerhilfe](docs/DEMO.md).

Für den vollständigen Kerncheck wird zusätzlich ein C-Compiler benötigt:

```sh
make check
```

Das umfasst Build, Unit- und Race-Tests, `go vet` und statische
Sicherheitsprüfungen. [Prüfergebnisse](docs/VERIFICATION.md).

## Aufbau

- `flow` ist die CLI für Profile, Schlüssel und Instanzzustände.
- `serving` verteilt signierte, unveränderliche Release-Sets und Desired State.
- SSH, VPN und PBP liefern die mitgelieferten Komponentenskripte.
- `examstation` ist nur deklariert; der Quellcode fehlt. `decepticon` bleibt eine
  externe Integration. Beide sind im Target-Runner nicht freigegeben.

Der vollständige Plattformablauf braucht zusätzliche Inputs, die fertige
Control-Route und eine Mehr-VM-Abnahme. Umfang und offene Arbeiten stehen in
[PROJECT_STATUS.md](PROJECT_STATUS.md) und der
[Abnahmematrix](docs/COMPLETION-AUDIT.md).

## Sicherheitsgrenzen

Release-, Desired-State- und Control-Keys sind getrennte Vertrauenswurzeln.
`FLOW_HOME` enthält private Schlüssel, Trust-Pins und Auditdaten und bleibt
außerhalb von Git. SSH-Hostkeys werden unabhängig geprüft und gepinnt;
`ssh-keyscan` allein genügt nicht. VNC bleibt auf Loopback.

[Threat Model](docs/THREAT-MODEL.md) und [Sicherheitsmeldungen](SECURITY.md).

## Dokumentation

- [Lokale Demo](docs/DEMO.md) und [Projektprofil](docs/PORTFOLIO.md)
- [Entwicklung und Build](docs/DEVELOPMENT.md)
- [Architektur](docs/adr/0001-platform-control-plane.md)
- [Geplanter Betriebsablauf](docs/QUICKSTART.md) und [Runbook](docs/OPERATOR-RUNBOOK.md)
- [Wiederherstellung](docs/RECOVERY-RUNBOOK.md)
- [VM-Lab](docs/LAB-E2E-RUNBOOK.md) und [PBP-Untersuchung](docs/PBP-INCIDENT.md)
- [Beiträge](CONTRIBUTING.md)

## Lizenz

[Apache License 2.0](LICENSE). Hinweise zu Drittanbieterkomponenten bleiben
in den jeweiligen Unterverzeichnissen erhalten.
