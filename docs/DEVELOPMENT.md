# Entwicklung

Dynamicflow ist in Entwicklung. Die Veröffentlichung des Quellcodes
qualifiziert kein Produktionsdeployment. Die Standardprüfung deckt den
mitgelieferten Go-Kern ab.

## Voraussetzungen

- Linux und die in `go.mod` angegebene Go-Version oder neuer.
- GNU make, Bash, Git (für ein Quellarchiv optional), OpenSSH/`ssh-keygen`,
  übliche Unix-Build-Werkzeuge und ein C-Compiler für Race-Tests.
- Die in `go.mod` und `go.sum` festgelegten Module, entweder im lokalen Cache
  oder über den konfigurierten Go-Proxy beziehbar. Die Befehle verweigern das
  Umschreiben des Modulmanifests; übergeordnete `go.work`-Dateien und ein
  benutzerspezifisches `GOENV` werden ignoriert.

## Kernbefehle

```sh
make build
.flow/bin/flow --version
.flow/bin/flow --help
make check
```

Die Ausgabe ist `.flow/bin/flow` und wird von Git ignoriert. `make check` ist ein
Alias für `make check-core`: Build, Unit-Tests, Race-Tests, vet und der
statische Sicherheitsvertrag. Derselbe Befehl läuft in der CI. Unit-Tests
verwenden temporäre Verzeichnisse und lokale Testserver; weder ein Lab-Inventar
noch ein Cloud-Konto ist nötig. Ein erfolgreicher Kerncheck ist keine Abnahme
einer Komponente oder des Produktionsbetriebs.

Die Integration der neuen Control-Route ist in Entwicklung. Entfernte
CLI-Lebenszyklus-, Enrollment-, Serving- und Remote-Publish-Befehle liefern
derzeit `control_route_unavailable`, bevor auf State zugegriffen, eine
Verbindung aufgebaut oder ein Kindprozess gestartet wird. `flow --help` listet
die unterstützten lokalen Operationen. Die Operator-Runbooks beschreiben einen
vollständigen Plattformablauf, den dieser Snapshot nicht ausführen kann.

## Optionale Offline-Vorbereitung

```sh
make vendor
make offline-build
```

`make vendor` lädt die festgelegten Abhängigkeiten bewusst herunter und legt
sie ab. Der erzeugte Baum `vendor/` im Wurzelverzeichnis wird ignoriert.
`make offline-build` prüft diesen Baum und deaktiviert Downloads von
Abhängigkeiten und Toolchains. Es baut nur das Go-Binary. Der Builder für
Plattform-Releases behält seine strengere Offline-Umgebung und braucht
zusätzlich die separat vorbereiteten Eingaben jeder Komponente. Ein fehlender
Vendor-Baum führt zu einem Hinweis auf die Vorbereitung statt zu einem
unverständlichen Modulfehler.

## Komponentenprüfungen und nicht verfügbare Integrationen

`make component-static` führt die mitgelieferten Prüfungen für SSH, VPN, PBP
und Serving aus. Diese haben zusätzliche Abhängigkeiten, die in den READMEs der
Komponenten beschrieben sind, und sind von der Kernprüfung für die
Veröffentlichung getrennt. Die Serving-Prüfungen verwenden lokale Testdienste
und synthetische Artefakte. Sie belegen keine echte externe Integration.

`make optional-component-static` schlägt ausdrücklich fehl, weil der Quellcode
von examstation und seine Tests nicht mitgeliefert werden. Es wird nicht
stillschweigend als bestanden gewertet.

Der externe Quellcode von Decepticon fehlt, wie im
[Integrationsstatus](../decepticon/README.md) erläutert. Seine Deklaration und
Fixture-Tests sind kein Nachweis einer deploybaren Implementierung. Keine der
beiden Integrationen ist im Target-Runner aktiviert.

Der aktuelle vollständige `flow release build` erwartet weiterhin die Eingaben
aller Komponenten. Dieser Snapshot bietet daher kein vollständiges
Plattform-Release. Keine Komponenten aus einem signierten Manifest entfernen,
um diese Anforderung zu umgehen. Die [Abnahmematrix](COMPLETION-AUDIT.md) hält
die verbleibende Arbeit fest.
