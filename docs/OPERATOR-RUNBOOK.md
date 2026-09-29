# Dynamicflow operator-runbook

> **in development.** die neue control-route blockiert derzeit entfernte
> lifecycle-, enrollment-, serving- und publish-aktionen mit
> `control_route_unavailable`. dieses runbook beschreibt den vollständigen
> zielablauf. nutzbare lokale befehle stehen in
> [DEVELOPMENT.md](DEVELOPMENT.md); fehlende komponenten in
> [PROJECT_STATUS.md](../PROJECT_STATUS.md).

dieses runbook beginnt nach dem initialen setup aus dem
[quickstart](QUICKSTART.md). die normale oberfläche ist ausschließlich
`flow`. komponenten-shellskripte sind interne übergangsimplementierungen.

## Grundregeln

1. private keys und secrets niemals in chat, ticket, git, argv oder logs
   kopieren.
2. vor jeder änderung zuerst den entsprechenden `--plan`-befehl verwenden,
   sofern vorhanden.
3. einen signatur-, hostkey-, persona- oder pfadfehler nie mit löschen oder
   „accept new“ umgehen.
4. normale lifecycle-operationen laufen über HTTPS. allgemeiner direktzugriff
   nur mit einem explizit sichtbaren `instance ssh`, `instance exec` oder
   `instance secret`. `test lab` nutzt zusätzlich feste, auditierte SSH-
   actions ohne freien remote-befehl.
5. cloud-firewall, DNS, accounts und abrechnung liegen außerhalb von `flow`.

## Lokaler state und audit

die auflösungsreihenfolge des operator-state ist:

1. globales `--home /ABS/PATH`;
2. `FLOW_HOME`;
3. `$XDG_STATE_HOME/dynamicflow`;
4. `$HOME/.local/state/dynamicflow`.

alle pfade müssen dem ausführenden benutzer gehören; verzeichnisse sind
`0700`, dateien `0600`, symlinks werden abgelehnt. wichtige lokale daten:

```text
keys/signing/                   Release-, Desired- und Control-Key
keys/operator/                  bewusst geteilte Betreiber-SSH-Keys
keys/instance/                  Standard-SSH-Key je Instanz
enrollments/                    öffentliche lokale Enrollment-Bindung
instances/<name>/instance.json Endpunkt und Hostkey-Metadaten
instances/<name>/known_hosts   einzelner gepinnter Hostkey
releases/                       Build-/Staging-Metadaten
serving/remote.json             gepinnte Serving-Bindung
logs/audit.jsonl                lokale Operator-Auditspur
```

private key-dateien nicht mit diagnoseausgaben sammeln. `flow key list` und
`flow instance list` liefern die benötigten public-metadaten.

## Exitcodes und JSON-vertrag

| code | bedeutung für normale CLI-befehle |
| --- | --- |
| `0` | erfolg |
| `1` | allgemeiner build-/laufzeitfehler |
| `2` | syntax/usage |
| `3` | konfiguration, lokaler state oder plattform |
| `4` | authentisierung/berechtigung |
| `5` | signatur-, digest- oder trust-verifikation |
| `6` | konflikt, busy, replay, revocation oder monotone generation |
| `7` | remote-/HTTPS-/systemd-fehler |
| `8` | teilzustand oder unbekannter ausgang; recovery nötig |

ein explizites `flow instance exec` gibt bei remote-fehlern den tatsächlichen
SSH-/remote-exitcode zurück; er ist nicht auf diese tabelle begrenzt.

für automation:

```sh
flow --json instance status NAME
flow --json instance logs NAME --component pbp
```

erfolg steht in stdout als `{"ok":true,...}`, fehler in stderr als
`{"ok":false,"error":{"code":...,"message":...,"next":...}}`. nicht nur
text parsen; exitcode und `ok` auswerten. `instance ssh` ist interaktiv und
lehnt `--json` ab. secret-reveal enthält das secret bewusst in stdout/JSON und
gehört nicht in automation.

`instance key finalize` führt ohne `--plan` nach der HTTPS-prüfung einen
sichtbaren, lokal auditierten proof über den gepinnten SSH-hostkey aus. mit
`--plan` findet kein SSH-proof statt.

für profil `pbp` übernimmt der periodische target-reconcile zusätzlich nur
eine feste teilmenge der lokalen JSONL-lifecycle-ereignisse in
`flow instance logs NAME --component pbp`: start, browserstart/-crash,
egress-ablehnung/-ausfall, cleanupfehler und das finite endergebnis. freie
meldungen, stderr, argv, ips, urls, pfade und persona-/profilwerte verlassen
die VM nicht. die bridge ist crash-idempotent und beeinflusst browser und
locks nicht. deshalb ist diese ansicht eine schnelle, verzögerte übersicht,
aber kein ersatz für die root-/benutzerprivaten runtime-logs oder das
qualifizierende forensikpaket.

## Tägliche zustandsprüfung

auf dem operator-rechner:

```sh
flow doctor
flow serving show
flow enroll list
flow instance list
flow instance status NAME
flow instance logs NAME
```

ein status älter als 15 minuten wird von der CLI als `STALE` markiert. ein
fehlender report zeigt `pending`, sofern ein desired state existiert. `ready`
bedeutet: die gemeldete generation wurde vollständig angewendet; es ersetzt
keinen reboot-, egress- oder PBP-soak-test.

auf dem serving-host selbst, mit dem bei provisionierung verwendeten state:

```sh
sudo flow --home /var/lib/dynamicflow-serving-operator status serving
sudo flow --home /var/lib/dynamicflow-serving-operator logs serving --lines 200
```

`flow status serving` ist eine lokale systemd-/release-prüfung, keine
remote-abfrage vom operator-rechner.

## Serving idempotent abgleichen

ein plan setzt ein bereits verifiziertes aktives release am angegebenen root
voraus:

```sh
sudo flow --home /var/lib/dynamicflow-serving-operator \
  start serving --plan \
  --public-url https://serving.example:8443 \
  --release-public-key /var/lib/dynamicflow-serving/trust/release.public.pem \
  --desired-public-key /var/lib/dynamicflow-serving/trust/desired-state.public.pem \
  --control-public-key /var/lib/dynamicflow-serving/trust/control.public.pem
```

der mutierende befehl verwendet dieselben expliziten werte:

```sh
sudo flow --home /var/lib/dynamicflow-serving-operator \
  start serving \
  --public-url https://serving.example:8443 \
  --release-public-key /var/lib/dynamicflow-serving/trust/release.public.pem \
  --desired-public-key /var/lib/dynamicflow-serving/trust/desired-state.public.pem \
  --control-public-key /var/lib/dynamicflow-serving/trust/control.public.pem
```

nach dem ersten erfolgreichen lauf übernimmt `flow` state-root, release-root,
listen-adresse, public-URL, dienstbenutzer und die drei absoluten
public-key-quellen aus der lokalen serving-referenz
`<FLOW_HOME>/serving/local.json` (schema 2). ohne erste angabe ist der
release-root `<state-root>/releases` und der dienstbenutzer
`dynamicflow-serving`. ein später explizit angegebener wert ersetzt den
gespeicherten wert erst nach erfolgreichem reconcile. die gespeicherten
public-key-quellen müssen deshalb dauerhaft existieren; binden sie nach dem
erstbootstrap die bereits kopierten dateien unter `<state-root>/trust/` mit
einem expliziten lauf ein, falls die ursprünglichen staging-dateien entfernt
werden sollen. danach ist ein flagloser reconcile reproduzierbar.

eine alte schema-1-referenz wird beim lesen nur nach striktem abgleich mit der
root-erzeugten config und TLS-identität im speicher auf schema 2 ergänzt. erst
der nächste erfolgreiche explizite `start serving` schreibt schema 2 atomar;
`status` mutiert die referenz nicht. der lauf:

- erhält ein vollständiges vorhandenes TLS-paar und ersetzt es nicht still;
- verweigert gleiche schlüssel für mehrere rollen;
- prüft das komplette aktive release vor systemd;
- startet als dedizierter `dynamicflow-serving`-benutzer;
- übergibt nur den release-root und `private/` als schreibbare bereiche an
  diesen benutzer; `.imports/` und der publish-lock bleiben privat, während
  trust, TLS und konfiguration rootkontrolliert sind;
- startet den dienst nur bei geänderter konfiguration neu.

die dazugehörigen modi und eigentümer sind verbindlich: state-root
`0751 root:dynamicflow-serving` (für andere nur traverse), release-root und
`sets/` `0755 dynamicflow-serving:dynamicflow-serving`, `.imports/` `0700`
und `.publish.lock` `0600`. `trust/` ist
`0755 root:dynamicflow-serving`; nur die drei public-key-pems sind `0644`.
damit kann ein nichtprivilegierter plan public trust und signierte sets
prüfen. `private/` bleibt dienstkontrolliert `0700`, `tls/`
`0750 root:dynamicflow-serving`; TLS-key, bootstrap und config bleiben
`0640 root:dynamicflow-serving`. das state-root-traverse-recht allein gewährt
keinen zugriff auf diese geschützten inhalte. der release-root muss ein
strikt separater unterbaum sein: nicht gleich dem state-root, nicht unter
`private/`, `trust/` oder `tls/` und ohne kollision mit `config.json` oder
`bootstrap.sh`.

eine fehlende hälfte des TLS-paars ist ein recovery-fall, kein anlass, die
andere hälfte zu löschen.

## Release-lifecycle

### Bauen und verifizieren

```sh
flow release build --rebuild --generation NEW_MONOTONE_GENERATION
flow release verify
```

das buildlog liegt im privaten operator-state unter
`logs/release-build.log`; die CLI gibt den vollständigen pfad aus. prüfen sie
bei fehlern dieses log, ohne secretdateien mit anzuhängen. auch dieses log ist
teil der geschützten zustandsgrenze: `flow` öffnet es mit `O_NOFOLLOW`, verlangt
besitzer, exakt `0600`, genau einen hardlink und dieselbe path-/FD-identität.
eine abweichende datei wird nicht überschrieben oder als builder-ausgabe
verwendet.

build, verify, publish und publish-plan verwenden denselben fail-fast
operator-lock `releases/operation.lock`. so können ein rebuild und eine
verifikation beziehungsweise ein streaming-upload niemals dieselben
`staged.json`- oder artefaktpfade gleichzeitig verändern und lesen. ist schon
eine operation aktiv, endet `flow` mit exitcode 6 und `release_busy`; warten
sie auf deren abschluss und wiederholen sie den befehl. löschen sie keinen
gehaltenen lock. ein lock mit falschem besitzer, einem modus ungleich `0600`,
mehreren hardlinks oder einem symlink wird als `release_lock` abgewiesen.

für einen reproduzierbaren vergleich dieselbe explizite generation, dieselben
quellen, vendor-caches und toolchains verwenden und die erste ausgabe vor dem
zweiten build in einen geschützten vergleichspfad kopieren. set-ID,
manifestinhalt, die private `staged.json` und alle artefakt-SHA-256 müssen
übereinstimmen. build-kindprozesse erhalten nur eine feste minimale umgebung;
beliebige operator-umgebungsvariablen werden nicht vererbt. persistentes
`GOENV`, ein äußeres `go.work` sowie globale git-konfiguration werden
ausgeschaltet. go verwendet ausschließlich die lokal installierte toolchain
und bereits verifizierte modul-caches (`GOPROXY=off`); ein fehlender input
bricht ab, statt eine toolchain oder ein modul aus dem netz nachzuladen. die
`signed-manifest.json`-bytes sind nur bei demselben release-signer direkt
vergleichbar; getrennt erzeugte state-roots besitzen absichtlich verschiedene
signer. signaturprüfung und reproduzierbarkeit sind zwei eigenständige gates.

jeder erfolgreich signierte build legt zusätzlich ein content-addressed
manifest im privaten verzeichnis
`<FLOW_HOME>/releases/manifest-history/` (`0700`/`0600`) ab. vor einer neuen
signatur vergleicht `flow` **alle** historischen manifeste sowie vorhandene
repository-artefakte. dieselbe kombination aus komponente, version und target
darf nie auf einen anderen dateinamen, digest oder eine andere größe zeigen.
ändert sich irgendein paketiertes byte, auch nur README, `VERSION` oder die
`flow`-binary, muss die betroffene komponentenversion erhöht werden. den
manifestkatalog nie löschen oder aus einem anderen operator-state mischen.
`<FLOW_HOME>/releases/manifest-history.index.json` (`0600`) checkpointet die
vollständige set-liste und höchste generation. fehlt ein checkpointeter
eintrag oder das verzeichnis, blockieren build, verify und publish; niemals
durch einen leeren katalog „reparieren“. nur zusammengehörige history,
checkpoint, stage, exportmanifest und signing-key aus einem verschlüsselten
backup restaurieren.
ein bestehendes stage ohne index sowie ein nichtleerer katalog ohne index
werden ausdrücklich **nicht** automatisch migriert: ein ausgedünnter rest darf
nicht zur neuen wahrheit werden. eine notwendige altzustandsmigration muss
außerhalb des normalen lifecycle als auditierte trust-domain-recovery erfolgen.

eine explizite build-generation unterhalb des katalog-high-water oder dieselbe
generation mit anderem set wird **vor** der signatur abgelehnt. ein
byteidentischer fixed-generation-rebuild bleibt erlaubt. ohne explizite zahl
verwendet `flow` bei gleichem zeitstempel oder uhr-rücklauf automatisch
`High-Water + 1`. das content-addressed history-manifest wird zuerst, der
kanonische export danach und `staged.json` als letzter commit-marker
geschrieben. verify und publish blockieren bei einer abweichung zwischen stage
und export bis zu einem erfolgreichen rebuild.

### Remote oder lokal atomar veröffentlichen

nach einem erfolgreichen `flow serving configure` ist gepinntes HTTPS der
standard:

```sh
flow release publish --plan
flow release publish
```

`--remote` erzwingt den remote-modus und scheitert ohne gültige gepinnte
serving-bindung:

```sh
flow release publish --remote --plan
flow release publish --remote
```

für einen ausdrücklich lokalen serving-root gilt stattdessen:

```sh
flow release publish --root /ABS/PATH/releases --plan
flow release publish --root /ABS/PATH/releases
```

`--root` ist immer ein lokaler dateisystempfad, kein remote-deploy; `--root`
und `--remote` sind gegenseitig ausgeschlossen. nur beim einmaligen
serving-erstbootstrap werden ein bereits lokal gültiges release-set und
`release.public.pem`, `desired-state.public.pem` sowie `control.public.pem`
über einen separat authentisierten weg bereitgestellt. nach der remote-bindung
benötigen folge-releases keinen manuellen datei-transfer mehr.

`--plan` ist ein echter policy- und dateisystem-preflight: lokal liest es den
zielkatalog ohne dateien anzulegen und prüft erstellbarkeit, owner-schreibmodi
sowie vorhandene publish-lock-metadaten; remote sendet es nur das signierte
manifest über einen control-signierten HTTPS-request an
`/v1/admin/releases/plan`. serving prüft
damit retained generationen, versionsbindungen, pfade, `current` und
manifest-historie, lädt aber kein bundle hoch und schaltet nichts um. der
echte publish wiederholt alle prüfungen unter dem serverseitigen lock, weil
sich zustand zwischen plan und apply ändern kann.

ein release-root unter einem gruppen- oder weltbeschreibbaren, nicht-sticky
ancestor wird bereits im plan abgelehnt. alle ancestors müssen root- oder
operator-/serving-owned sein; `/tmp`-artige eltern sind nur mit korrekter
sticky-semantik zulässig. während publish bleibt der root-FD geöffnet und
`dev/inode` wird vor jeder commit-grenze erneut geprüft. den release-root daher
nicht während eines laufs verschieben, bind-mounten oder austauschen.

der release-signing-key signiert ausschließlich das manifest. der getrennte
control-key signiert den SHA-256-digest des kanonischen streaming-bundles und
bindet ihn an den release-import-endpunkt. beide private keys bleiben auf dem
operator; serving besitzt nur die public keys. vor dem upload verifiziert der
operator signatur und alle artefakte. serving prüft die release-signatur,
bundlegröße sowie jede signierte artefaktgröße und jeden digest erneut und
aktiviert das set erst danach durch einen atomaren `current`-zeigerwechsel.
manifest, komponentenanzahl und gesamtbundle besitzen harte bounds. quellen,
staging-verzeichnisse und ziele werden descriptor-relativ ohne symlink-following
und mit single-link-prüfung geöffnet. klartext- und tar.gz-inhalte mit
PEM-/OpenSSH-private-key-markern werden vor signatur beziehungsweise import
abgelehnt.

rollback-schutz betrachtet nicht nur den veränderbaren `current`-pointer,
sondern die höchste generation aller vollständig signatur-, mode- und
digestverifizierten retained sets sowie die signierten manifeste unter
`<release-root>/history/<set-id>/signed-manifest.json`. nach einem erfolgreichen
scan migriert publish fehlende tombstones zweiphasig; ein widersprüchlicher
altbestand schreibt dabei keine zufällige teilhistorie. ein zurückgesetzter
pointer oder normales artefakt-pruning erlaubt daher kein zwischenrelease und
kein versions-rebinding. gleiches gilt remote bereits vor dem upload gegen die
lokal gepinnte operator-high-water-marke. referenzierte sets dürfen nicht
manuell entfernt werden; pruning benötigt einen separaten auditierten
workflow und darf `history/` nie entfernen.
bestehende desired states bleiben dabei an ihre eigene set-ID gebunden und
beziehen manifest sowie artefakte weiterhin über den unveränderlichen
set-ID-pfad. `current` bindet nur nachfolgend signierte rollouts; es ist kein
globales stilles upgrade. referenzierte vorgänger-sets nicht manuell löschen.

der einzelne upload ist client- und serverseitig auf zwei stunden begrenzt.
bei einem transportfehler kann der ausgang unbekannt sein, etwa wenn nur die
antwort auf eine erfolgreiche aktivierung verloren ging. serving akzeptiert
einen identischen retry idempotent; deshalb zuerst status und audit prüfen und
dann exakt dasselbe set wiederholen, statt eine niedrigere generation zu bauen
oder den zeiger manuell zu ändern. auch bei einem unklaren oder zurückliegenden
serving-zustand wird der lokal akzeptierte release-high-water-mark niemals
heruntergestuft.

bei einem lokalen abbruch nach dem set-rename erkennt plan
`resume_committed_set=true`. wenn dieses set weiterhin vollständig signatur-,
digest-, owner- und modeverifiziert ist, darf publish fehlende history und
`current` auch ohne die früheren quellartefakte fertigstellen. remote wird der
identische verifizierte bundle-upload wiederholt; es gibt keinen separaten
ungeprüften aktivierungsendpunkt.

gleiche generation mit anderem inhalt und niedrigere generation werden
abgelehnt. bei einer fehlerhaften neuen version wird ein korrigiertes,
signiertes set mit höherer generation gebaut; ein stiller downgrade ist kein
recovery-verfahren. `version_conflict` bedeutet dagegen ausdrücklich:
komponentenversion erhöhen; weder set noch operator-historie löschen.

## Schlüsselverwaltung

### Eigenständiger operator-key

```sh
flow key create --name operator --scope operator
flow key list --scope operator
flow key rotate --name operator --scope operator
flow key revoke --name operator --scope operator
```

ein geteilter operator-key vergrößert die schadensreichweite. standard-
enrollment verwendet deshalb `--scope instance` und den instanznamen.

### Per-instance-SSH-key rotieren

für eine standardinstanz `NAME`:

```sh
flow key rotate --name NAME --scope instance
flow instance apply NAME --profile CURRENT_PROFILE --plan
flow instance apply NAME --profile CURRENT_PROFILE
```

der erste apply veröffentlicht eine überlappung aus altem und neuem public
key. warten, bis die instanz mindestens diese desired-generation als applied
meldet:

```sh
flow instance status NAME
```

dann denselben apply ein zweites mal ausführen. erst dieser zweite,
bestätigungsgebundene schritt entfernt den alten public key:

```sh
flow instance apply NAME --profile CURRENT_PROFILE --plan
flow instance apply NAME --profile CURRENT_PROFILE
flow instance status NAME
```

während der überlappung kann `flow instance ssh` bereits den neuen lokalen
private key auswählen; bis die instanz die erste generation angewendet hat,
kann dieser login erwartungsgemäß scheitern. nicht vorzeitig den alten key
widerrufen.

bei einem geteilten operator-key muss jede zugeordnete instanz separat durch
diese zwei apply-generationen geführt werden.

## Enrollment und profile

```sh
flow profile list
flow profile show PROFILE
flow enroll create --name NAME --profile PROFILE --ttl 15m
flow enroll list
```

`enroll create` prüft das aktive release und löst den vollständigen graphen.
für PBP muss die ausgabe exakt
`ssh -> ssh-gui -> vpn-pbp-de -> pbp` enthalten. die profile `decepticon` und
`examstation` sind aktuell deklarativ vorhanden, im festen target-runner aber
noch nicht freigegeben; für sie keinen realen enrollment-apply als erfolg
einplanen.

optional kann der SSH-endpunkt bereits beim erstellen gebunden werden:

```sh
flow enroll create --name NAME --profile PROFILE \
  --host 192.0.2.20 --ssh-user admin --ssh-port 22
```

das speichert nur die adresse und stellt keine verbindung her. nach ausgabe
des codes ist der lokale secretwert absichtlich nicht wieder abrufbar. bei
unsicherheit einen code nicht in dateien „retten“, sondern ablauf/revocation
gemäß recovery-runbook behandeln.

## Desired state anwenden

```sh
flow instance apply NAME --profile PROFILE --plan
flow instance apply NAME --profile PROFILE
```

der operator signiert eine neue monotone desired-generation und sendet sie per
control-authentisiertem HTTPS. der befehl wartet nicht auf die installation;
die instanz muss anschließend reconciliieren und status melden. es gibt keinen
SSH-fallback.

der target-apply arbeitet phasenweise mit preflight, fester installation,
verifikation, journal und fail-closed. root-only detail-logs liegen auf der VM
unter `/var/lib/dynamicflow/instance/apply/logs/<phase>.log`; serving erhält
nur finite bereinigte ereignisse.

enrollment installiert vor dem lesen des codes zwei feste units:

```text
dynamicflow-instance-reconcile.service
dynamicflow-instance-reconcile.timer
```

der persistente timer läuft im fünf-minuten-takt mit begrenztem jitter und
startet nur den root-oneshot `flow instance-runtime reconcile` für den festen
state-root. er ist kein allgemeiner jobkanal und startet weder SSH noch PBP neu.
ein apply wartet daher nicht synchron auf die installation; status bis zur
bestätigten desired-generation beobachten.

die erste apply-phase ist immer `flow`. bei geänderten binary-bytes wird die
bisher laufende binary vor dem atomaren replace content-addressed und root-only
unter `/var/lib/dynamicflow/instance/apply/runtime-recovery/` gesichert. die
alte invocation meldet danach ausschließlich
`runtime_handoff=true`/`applying`, führt keine weitere profilphase aus und
setzt den checkpoint nicht vor. der nächste timerlauf startet
`/usr/local/bin/flow` neu und setzt denselben signierten plan fort. bleibt
dieser folge-lauf aus oder kann die neue binary nicht starten, gilt das nicht
als erfolgreicher apply; verwenden sie die providerkonsolen-prozedur im
recovery-runbook.

## SSH, exec und hostkey

```sh
flow instance bind NAME --host HOST --ssh-user USER --ssh-port 22
flow instance hostkey pin NAME \
  --public-key-file /ABS/PATH/ssh_host_ed25519_key.pub
flow instance status NAME
flow instance ssh NAME
flow instance exec NAME -- COMMAND ARG...
```

`bind` kontaktiert den host nicht. vor dem ersten SSH wird
`/etc/ssh/ssh_host_ed25519_key.pub` über die authentisierte providerkonsole als
kleine reguläre datei zum operator exportiert und dort out-of-band verglichen.
`hostkey pin` übernimmt ausschließlich diese datei, stellt selbst keine
netzwerkverbindung her und verlangt eine aktive lokale enrollment-bindung.

`status` importiert keinen hostkey. es zeigt den gemeldeten fingerprint als
nicht autorisierende beobachtung und vergleicht ihn mit dem unabhängigen pin;
eine abweichung stoppt. damit kann ein kompromittiertes serving den ersten
SSH-trust nicht ersetzen.

`instance exec` ist ein direkter, expliziter SSH-befehl. die auditspur speichert
nicht den klartext, sondern SHA-256 der argv-folge und argc. trotzdem stehen
die argumente während des SSH-aufrufs in der lokalen prozessliste: keine
passwörter, tokens oder accounts als argument übergeben.

nach einer bewusst erneuerten SSH-hostidentität den neuen public key über eine
authentisierte providerkonsole als kleine reguläre datei beziehen, fingerprint
separat vergleichen und erst dann:

```sh
flow instance hostkey rotate NAME \
  --public-key-file /ABS/PATH/ssh_host_ed25519_key.pub
```

pin und rotation machen keine netzwerkverbindung, lehnen
symlinks/überlange dateien ab und auditieren die fingerprints. `ssh-keyscan`
darf diese datei nie liefern.

## GUI/VNC

```sh
flow instance ssh NAME --gui --local-port 5901
```

danach verbindet ein lokaler VNC-client zu `127.0.0.1:5901`. erwartet sind ein
gesperrter, unprivilegierter benutzer `malwarelab`, ein aktiver
`tigervncserver@:1.service`, ausschließlich loopback-listener und deaktiviertes
clipboard. `flow` öffnet keine firewall.

das passwort wird nur bewusst angezeigt:

```sh
flow instance secret reveal NAME --secret vnc
flow instance secret rotate NAME --secret vnc
```

beide befehle warnen und auditieren. über den gepinnten SSH-pfad wird nur der
feste root-one-shot `flow instance-runtime secret reveal|rotate --secret vnc`
mit konstanten argumenten gestartet; weder passwort noch pfade oder shellcode
stehen in argv, umgebung oder audit. rotation öffnet home, `.vnc`,
`.config/tigervnc` und passwortdateien descriptor-relativ mit `O_NOFOLLOW`,
verlangt exakte besitzer/modi und einen einzelnen hardlink, schreibt secret und
beide TigerVNC-dateien atomar und synchronisiert dateien sowie verzeichnisse.
erst aktive feste unit, `VncAuth`, korrektes `PasswordFile`, port 5901 und reine
loopback-listener schließen die rotation ab. andernfalls werden die zuvor
verifizierten bytes atomar restauriert; ist auch das nicht sicher möglich,
bleibt VNC gestoppt. normale befehle geben das passwort nicht aus.

## PBP-betrieb

vor jedem start prüft PBP einen deutschen mullvad-egress. bei falschem egress,
relay-/IP-wechsel oder ausgeschöpftem prüf-backoff wird der kontext offline
geschaltet und kontrolliert beendet. es gibt keinen auto-restart.

technische runtime-logs liegen als höchstens acht rotierte JSONL-dateien unter:

```text
/home/malwarelab/.local/state/dynamicflow/pbp/logs/runtime-*.jsonl
```

das verzeichnis ist `0700`, dateien `0600`. ein desktopfehler zeigt einen
dialog beziehungsweise eine notification mit konkreter handlung und logpfad.
die stabile persona liegt root-eigen unter
`/etc/toolkit/pbp-persona.json`, das profil unter
`/home/malwarelab/.local/share/toolkit-pbp/profile`. beide niemals zum
„reparieren“ löschen.

der reale soak und die schließen-/neustartzyklen stehen im
[lab-/E2E-runbook](LAB-E2E-RUNBOOK.md); ein lokaler virtueller 30-minuten-test
ist kein ersatz.

## Revocation

```sh
flow instance revoke NAME
```

der operator veröffentlicht einen signierten desired state ohne autorisierte
SSH-keys und deaktiviert sofort die lokale per-instance SSH-identität sowie
die lokale instanzbindung. die ausgabe sagt ausdrücklich, dass die remote-
bestätigung noch aussteht. bis ein HTTPS-status die revocation bestätigt oder
die VM über providerkontrolle isoliert wurde, ist die zielseite nicht als
bereinigt anzusehen.

der feste target-one-shot führt für revocation keinen installer und kein SSH
aus. er sperrt lokal fail-closed und meldet signiert über ausgehendes HTTPS:

```text
state=revoked, revoked=true, fail_closed=true
desired_generation=<Revocation-Generation>
applied_generation=<letzter Checkpoint>
ssh: state=blocked, code=revoked
```

dazu gehört genau ein finites ereignis `ssh/critical/phase_fail_closed` mit
code `revoked`. erst dieser status ist die remote-bestätigung. weitere normale
status-/loguploads derselben widerrufenen identity werden abgewiesen. scheitert
nur die bestätigung, bleibt die lokale sperre aktiv; exitcode 8
(`reporting_partial`) und der nächste timerlauf wiederholen den ack.

## Decommission

auf einer disposable mullvad-VM vor dem löschen über providerkonsole oder einen
bewussten expliziten zugriff:

```sh
sudo mullvad auto-connect set off
sudo mullvad lockdown-mode set off
sudo mullvad disconnect --wait
sudo mullvad account logout
```

dies gibt einen mullvad-geräteplatz frei, schwächt aber bewusst fail-closed und
gehört nur zur endgültigen außerbetriebnahme. danach VM/volume providerseitig
löschen, lokale instanz revoken und audit-/testergebnis aufbewahren. private
SSH-key-dateien werden nicht automatisch vernichtet, damit audit und
forensische zuordnung erhalten bleiben.
