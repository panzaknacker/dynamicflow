# Architekturübersicht

## Zweck

Dynamicflow strukturiert wiederverwendbare Linux-VM-Umgebungen. Konfiguration,
Identitäten und Zustandsänderungen sollen nachvollziehbar bleiben, auch wenn
Umgebungen neu erstellt oder bei einem anderen Hosting-Anbieter betrieben werden.
Diese Übersicht beschreibt den Go-Kern und sein Architekturziel; sie ist keine
Installationsanleitung oder Produktionsfreigabe.

## Bedienung und Verarbeitung

Die Terminaloberfläche (TUI), die Befehlszeile (CLI) und JSON-Ausgaben verwenden
[gemeinsame Application Services](../internal/application/). Die Oberflächen
übernehmen Eingabe und Darstellung, die Services die fachlichen Regeln und
Zustandsübergänge. Eine Aktion soll dadurch dieselbe Bedeutung haben, unabhängig
von ihrer Darstellung.

Die aktive Systemauswahl ist ausdrücklich. Eine erwartete System-ID bindet
geeignete Befehle an das zuvor gewählte System. Diagnosen unterscheiden lokale
Konsistenz von noch ausstehenden Schritten; ein lokal gesunder Zustand bestätigt
nicht automatisch eine funktionsfähige entfernte Umgebung.

## Rollen im Architekturziel

- **Operator:** der lokale Bedienrechner mit Konfiguration und privaten Identitäten.
- **Control:** der vorgesehene Zugriffsknoten für überprüfte Managementverbindungen.
- **Serving:** der Verteilserver für signierte Releases und Zustandsvorgaben.
- **Instances:** die verwalteten VMs, die ihren Zustand mit diesen Vorgaben abgleichen.

Diese Rollen sind getrennt. Beispielsweise ist ein Schlüssel für
Serving-Verwaltung nicht die Identität eines Control-Knotens. Private
Zielschlüssel bleiben beim Operator.

## Zustände und Vertrauensgrenzen

[Signaturen](../internal/signing/) und [Release-Prüfungen](../internal/release/)
binden Artefakte an den vorgesehenen Stand. Der
[Zustandsabgleich](../internal/reconcile/) behandelt gewünschte Konfiguration und
Aktivierung getrennt. Persistierte Schritte und überprüfte Identitätsbindungen
sind wichtig, wenn ein Vorgang unterbrochen und später fortgesetzt wird.

Fehlende Voraussetzungen sollen einen Ablauf anhalten. Eine erfolgreiche
SSH-Verbindung allein bestätigt weder alle Identitäten noch die Freigabe
weiterer Aktionen. Lokaler Zustand in `FLOW_HOME` enthält private Schlüssel,
Trust-Pins und Auditdaten und gehört nicht in die Veröffentlichung.

## Verfügbarer Umfang und Grenzen

Der lokale Kern umfasst Systeminitialisierung, Systemauswahl, Diagnosen,
Profilübersichten und Release-Werkzeuge. Entfernte Lifecycle-, Enrollment- und
Serving-Aktionen bleiben hinter `control_route_unavailable` gesperrt. Einzelne
Bootstrap-Schritte sind getrennt von einer vollständigen Control-Route zu betrachten.

Das Profil `decepticon` ist eine nicht installierbare externe Integration;
die eigentlichen Toolquellen werden nicht mitgeliefert. Auch `examstation`
fehlt. Das Browser-Toolkit ist für normale Releases gesperrt.

`make demo` zeigt einen lokalen Ablauf ohne Cloud-VM. `make check` ist das
lokale Prüfgate. Solche Prüfungen ersetzen weder reale VM-Nachweise noch eine
Produktionsfreigabe. Der dokumentierte Umfang endet an diesen Grenzen.
