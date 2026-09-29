# Sicherheitsrichtlinie

## Unterstützungsstatus

Dynamicflow ist in Entwicklung und nicht produktionsfreigegeben. Es gibt noch
keine unterstützte Version.

## Sicherheitslücken melden

Keine Schwachstelle mit echten Schlüsseln, .flow-Inhalten, Hostinventaren oder
Release-State als öffentliches Issue melden. Wenn aktiviert, GitHubs private
Vulnerability-Reporting-Funktion verwenden; andernfalls zuerst den Maintainer
über sein GitHub-Profil kontaktieren.

Berichte sollten Commit, betroffene Trust-Grenze, erwartete Signatur- oder
Pin-Prüfung und eine minimale Reproduktion mit Wegwerf-VMs enthalten.

## Testgrenze

Nur ausdrücklich als disposable markierte eigene Systeme verwenden. E2E- und
Soak-Läufe dürfen keine fremden oder produktiven Hosts verändern.
