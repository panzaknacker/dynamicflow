# Gehostete CI

## Prüfversuch vom 01.10.2026

GitHub Actions waren vor der Durchsicht deaktiviert. Die vorhandenen Prüf- und
Secret-Scan-Workflows wurden kurz aktiviert und manuell gestartet:

- [Prüflauf](https://github.com/panzaknacker/dynamicflow/actions/runs/36853153233)
- [Secret-Scan](https://github.com/panzaknacker/dynamicflow/actions/runs/36853165889)

Beide endeten mit `startup_failure`, bevor ein Job angelegt wurde. Jobs-API und
Check-Run-Liste blieben leer; Runner-Logs oder Fehleranmerkungen waren nicht
verfügbar. Der genaue Startgrund wurde über die API nicht ausgegeben.
In diesen gehosteten Läufen wurden keine Tests ausgeführt.

Actionlint 1.7.12 akzeptierte beide Workflow-Dateien. Die festgelegte
Checkout-Aktion existiert. Diese Prüfungen diagnostizieren den Startfehler nicht.

Actions wurden auf den ursprünglichen deaktivierten Zustand zurückgestellt,
um weitere Fehlmeldungen bei Dokumentationsänderungen zu vermeiden. Die
fehlgeschlagenen Läufe bleiben sichtbar. Nach Klärung der Ursache die Workflows
gezielt aktivieren und beobachten. Lokale Ergebnisse sind getrennt dokumentiert.

[Projektstatus](../PROJECT_STATUS.md)
