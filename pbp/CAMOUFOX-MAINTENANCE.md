# Camoufox-Wartung und Release-Freigabe

PBP aktualisiert camoufox nicht automatisch. browser-updates sind
sicherheitsänderungen und müssen geprüft, gepinnt und getestet werden, bevor sie
in ein release gelangen dürfen.

`browser-maintenance.py` hat zwei modi:

- `release` ist eine offline laufende, fail-closed prüfung von
  `browser-assets.lock` gegen die kurzlebige geprüfte policy in
  `browser-security-policy.json`.
- `audit` liest metadaten aus der offiziellen GitHub-API, den
  mozilla-produktdetails und PyPI. es lädt keinen browser herunter und
  bearbeitet nie eine der beiden eingabedateien.

den audit bei der vorbereitung eines updates ausführen:

```sh
./browser-maintenance.py audit
./browser-maintenance.py audit --json > /tmp/pbp-browser-audit.json
```

die offline-freigabe unmittelbar vor dem erstellen eines releases ausführen:

```sh
./browser-maintenance.py release
```

ein release ist nur erlaubt, wenn alle folgenden bedingungen erfüllt sind:

1. das review ist nicht abgelaufen und hat die entscheidung `approved`.
2. gesperrtes browser-repository, release-tag, tag-commit, asset-namen, URLs und
   SHA-256-digests stimmen exakt mit der geprüften herkunft überein.
3. die gecko-version des browsers erreicht mindestens die geprüfte
   mozilla-sicherheits-baseline.
4. die exakte version des python-wrappers und der wheel-digest stimmen mit dem
   review überein.

es gibt absichtlich keine übersteuerung per umgebungsvariable. ein nicht
verfügbares netzwerk schwächt die release-freigabe nicht, weil die
release-prüfung offline läuft. ein nicht erreichbarer offizieller endpunkt lässt
den online-audit fehlschlagen, statt anzunehmen, dass das alte review noch
aktuell ist.

## Die Pins aktualisieren

1. das aktuelle camoufox-checkpoint-release und seine änderungen lesen. sein tag
   in einen vollständigen 40-stelligen commit auflösen. ein verschobenes tag
   als andere quelle behandeln.
2. das aktuelle mozilla-release und die sicherheitsmeldungen lesen. die
   mindestversion von gecko muss jedes für den release-kanal relevante
   sicherheitsupdate enthalten. ein neueres camoufox-tag genügt nicht, wenn
   seine gecko-basis unter diesem minimum bleibt.
3. die digests beider linux-release-assets anhand offizieller GitHub-metadaten
   prüfen. in einen temporären review-ort herunterladen und jeden SHA-256
   unabhängig berechnen. nie eine asset-URL mit `/latest/` verwenden.
4. den exakten dateinamen und digest des PyPI-wheels prüfen. die installation
   mit verpflichtenden hashes und nur aus binärpaketen beibehalten.
5. einen reproduzierbaren build aus dem geprüften camoufox-commit bevorzugen.
   SBOM und build-attestierung festhalten. aktuelle upstream-tags und
   release-commits sind nicht signiert; ein hash allein authentifiziert inhalte
   daher erst nach dem ersten review.
6. `browser-assets.lock` und `browser-security-policy.json` gemeinsam
   aktualisieren. das review-fenster auf höchstens sieben tage begrenzen.
   `disposition` erst auf `approved` setzen, nachdem archivprüfung,
   launcher-tests, fingerprint-konformitätstests und ein echter netzwerk- und
   egress-test in einer wegwerf-VM bestanden sind.
7. den vendor-cache neu bauen, die vollständigen statischen prüfungen für beide
   architekturen ausführen und danach `browser-maintenance.py release`
   ausführen.

stand 27.07.2026 ist die sicherheits-baseline der mozilla-releases firefox
153.0. der neueste geprüfte camoufox-checkpoint ist 152.0.4-beta.28, und der
PBP-lock steht auf 150.0.2-beta.25. die policy blockiert releases daher bewusst,
bis ein geprüfter camoufox-build die sicherheits-baseline erreicht.
