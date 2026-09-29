# Warum dynamicflow

Für meine offensive Security Research habe ich unterschiedliche Hosting-Anbieter
genutzt, auch zur Kostenoptimierung. Bei einem Wechsel wollte ich VMs und Nodes
schnell wieder vorbereiten können, ohne ähnliche Umgebungen jedes Mal neu
zusammenzustellen. Daraus entstand dynamicflow: wiederverwendbare Profile für
flexible Research-Umgebungen in Labs und autorisierten Tests.

Private Varianten habe ich vielfach selbst für Research eingesetzt. Ihre genaue
Zuordnung zu diesem Snapshot ist noch offen. Hier lässt sich der lokale Go-Kern
ausprobieren; die neue Remote-Control-Route befindet sich im Umbau.

## Entscheidungen im Code

**Profile beschreiben den Aufbau.** Komponenten und ihre Abhängigkeiten werden
aufgelöst, bevor eine Umgebung aufgebaut wird. Noch nicht verfügbare
Integrationen bleiben als solche erkennbar.
[Profilauflösung](../internal/cli/profile.go), [Definitionen](../profiles/).

**Signaturen sind an ihren Zweck gebunden.** Release-, Desired-State- und
Control-Aufgaben haben getrennte Schlüssel. Verändert sich Inhalt, Domäne oder
Schlüssel, muss die Prüfung scheitern.
[Signaturen](../internal/signing/), [Release-Verifikation](../internal/release/).

**Unfertige Remote-Wege bleiben gesperrt.** Ein direkter Zugriff darf die neue
Control-Grenze nicht umgehen. Die CLI bricht betroffene Aktionen vor State-,
Netzwerk- oder Prozesszugriff ab.
[Remote-Sperre](../internal/cli/control_route_gate.go).

## Ausprobieren

`make demo` zeigt Initialisierung, Profile, Signaturprüfung und die erwartete
Remote-Sperre. [Anleitung](DEMO.md), [Prüfstand](VERIFICATION.md).

Als Nächstes stehen ein begrenzter Remote-Ablauf über die neue Control-Route
und seine Prüfung in Wegwerf-VMs an. Vollständiger Plattform-Release,
Vier-VM-Lauf und PBP-Soak sind eigene Abnahmen; siehe
[PROJECT_STATUS.md](../PROJECT_STATUS.md).
