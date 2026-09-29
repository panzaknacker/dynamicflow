# Optionale Decepticon-Integration

dynamicflow enthält eine integration und ein VM-datapack für einen optionalen
externen decepticon-quellbaum. der drittanbieter-quellcode ist in diesem
portfolio-repository bewusst nicht enthalten und wird nicht als eigene arbeit
ausgegeben.

um diese integration zu nutzen, die abhängigkeit separat beschaffen, ihre
lizenz und ihren sicherheitsumfang prüfen und beim ausführen von
`make-release.sh` die variable `DECEPTICON_REPO` auf diesen checkout setzen. das
release-skript bricht fail-closed ab, wenn der benötigte quellcode oder der
build-einstiegspunkt fehlt.

erzeugte bundles, kopierte quellbäume, zugangsdaten und release-artefakte
müssen außerhalb von git bleiben.
