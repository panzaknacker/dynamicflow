# Abnahmematrix

dieses dokument beschreibt den veröffentlichten quell-snapshot, nicht ein
privates lab oder einen früheren arbeitsstand. dynamicflow bleibt **in
entwicklung**. der aktuelle umfang ist ein lokal baubarer und testbarer
go-control-plane-kern.

| prüfstufe | umfang und nachweis | verbleibende anforderung |
| --- | --- | --- |
| kern-build | `make build` verwendet festgelegte module und erzeugt `.flow/bin/flow` | ausführung in gehosteter CI |
| kern-regressionsprüfungen | `make check`: build, unit-tests, race-tests, vet, statische sicherheitsverträge | das prüfergebnis für jeden kandidaten-commit festhalten |
| offline-kern-build | `make vendor`, danach `make offline-build` | unabhängig vorbereitete eingaben und vergleich wiederholter builds |
| mitgelieferte komponentenprüfungen | `make component-static` | separat festhalten; die kern-CI ist kein nachweis ihrer ausführung |
| integration der control-route | in entwicklung; entfernte CLI-lebenszyklusaktionen liefern `control_route_unavailable` | die neue route fertigstellen und unabhängig qualifizieren |
| examstation-integration | in entwicklung; deklarationen existieren, der quellcode fehlt | implementierung, review und unabhängige tests |
| decepticon-integration | in entwicklung; externer quellcode wird nicht mitgeliefert | prüfung von umfang und abhängigkeiten; fixture-tests qualifizieren die integration nicht |
| vollständiges signiertes plattform-release | in entwicklung; der builder erwartet jede komponente | vollständig vorbereitete eingaben, reproduzierbarkeit und prüfnachweise |
| echtes HTTPS-enrollment und recovery | lokale verträge und synthetische tests existieren | ausführung in wegwerf-VMs und bereinigte ergebnisse |
| vier-VM-qualifikation | nicht qualifiziert | unabhängig geprüftes host-vertrauen, ausdrückliches wegwerf-inventar und ein vollständiges ergebnis |
| PBP-stabilität | echter 30-minuten-soak und nachweis des lebenszyklus fehlen | korrelierte laufzeitnachweise und ein erfolgreicher echter soak |
| produktionsreife | nicht belegt | alle relevanten prüfstufen für komponenten, recovery und umgebung sowie eine gepflegte support-richtlinie |

## Umgang mit Nachweisen

unit-tests, gemockte artefakte und loopback-testserver belegen lokale verträge.
sie belegen weder externes VPN-verhalten noch recovery nach VM-neustart,
desktop-stabilität oder produktionsverfügbarkeit. private laufzeitnachweise
außerhalb von git aufbewahren und nur bereinigte zusammenfassungen
veröffentlichen, die an eine bestimmte quellrevision und umgebung gebunden sind.

der [entwicklungsleitfaden](DEVELOPMENT.md) legt die unterstützten lokalen
einstiegspunkte fest. das [lab-runbook](LAB-E2E-RUNBOOK.md) und die
[PBP-untersuchung](PBP-INCIDENT.md) bleiben entwicklungsdokumente; ihre
abläufe und historischen beobachtungen sind keine abnahme dieses snapshots.
