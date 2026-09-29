# Dynamicflow quickstart

> the new control-route integration is also in development. remote lifecycle
> operations currently return `control_route_unavailable` before connection or
> process execution. the operator sequences below document the intended full
> platform flow, not an available remote CLI in this snapshot.
>
> **in development: full platform procedure.** steps after the local core
> build require component inputs that are not included in this source
> publication, notably examstation and the external decepticon dependency.
> they are not a working deployment quickstart for a fresh clone. start with
> [DEVELOPMENT.md](DEVELOPMENT.md) for the supported local build and tests.
> the offline policy below applies to platform releases; normal `make build`
> uses pinned go modules without requiring a generated vendor tree.

dieser quickstart beschreibt den aktuellen control-plane-pfad. er trennt
explizit den bequemen erstbootstrap von einem download-prüfen-ausführen-weg.
weder die vier realen lab-vms noch der PBP-soak gelten allein durch diese
schritte als bestanden.

## 1. operator vorbereiten

auf dem vertrauenswürdigen operator-rechner:

```sh
cd /path/to/dynamicflow
make build
install -d -m 0700 "$HOME/.local/bin"
install -m 0755 .flow/bin/flow "$HOME/.local/bin/flow"
export PATH="$HOME/.local/bin:$PATH"
export FLOW_HOME="$HOME/.local/state/dynamicflow"
flow init
flow doctor
```

`flow init` erzeugt drei getrennte Ed25519-paare für release-signing,
desired-state-signing und serving-control. private dateien bleiben in
`FLOW_HOME` mit modus `0600`. sichern sie dieses verzeichnis verschlüsselt und
offline; kopieren sie es nicht auf serving oder eine ziel-VM.

## 2. profile und release prüfen

```sh
flow profile list
flow profile show pbp
flow release build --rebuild --generation 2026072301
flow release verify
flow release publish --root "$FLOW_HOME/serving/releases" --plan
flow release publish --root "$FLOW_HOME/serving/releases"
```

die generation ist eine monotone positive zahl. für zwei reproduzierbare
vergleichsbauten muss sie identisch sein; für einen nachfolger muss sie höher
als die aktive generation sein.

`--rebuild` benötigt die komponentenspezifischen build-abhängigkeiten und die
vorab geprüften offline-/vendor-caches. der aktuelle builder baut SSH, VPN,
PBP für amd64/arm64, decepticon, examstation und `flow`. der decepticon-builder
arbeitet dabei bewusst aus dem exakten maßgeblichen working tree; ein dirty
tree wird im datapack als solcher markiert, aber nicht still durch ein altes
artefakt ersetzt. fehlt ein builder, vendor-input oder exaktes ergebnis,
bricht der build vor der signatur ab. die alten serving-snapshot-skripte sind
kein alternativer normaler publish-pfad.

der build ist auch für go strikt offline: benutzer-`GOENV`, äußere
`go.work`-dateien und globale git-konfiguration werden ignoriert, automatische
toolchain-/moduldownloads sind aus. installieren und füllen sie deshalb die
dokumentierten toolchains und caches vor dem release-gate bewusst auf.

für den einmaligen serving-erstbootstrap wird hier der lokale release-root
`$FLOW_HOME/serving/releases` ausdrücklich mit `--root` gewählt.
`flow release publish` prüft alle bytes und schaltet dort atomar `current` um.
ohne konfigurierte remote-bindung verwendet ein flagloser publish denselben
lokalen standard; das explizite `--root` macht die vertrauensgrenze im
bootstrap-ablauf sichtbar.

`current` bestimmt nur, welches set für einen neu signierten desired state
verwendet wird. bereits ausgestellte desired states laden weiterhin exakt ihr
signiertes, unveränderliches set über dessen set-ID. deshalb dürfen alte sets
nicht manuell gelöscht werden, solange eine instanz oder ein gültiges
enrollment noch darauf verweist.

## 3. serving initial bereitstellen

bevor ein serving-knoten existiert und gepinnt werden kann, braucht sein
einmaliger initialer bootstrap einen separat authentisierten
dateiübertragungsweg. folge-releases benötigen nach `flow serving configure`
keinen manuellen transfer mehr. beim erstbootstrap werden ausschließlich
übertragen:

- die gebaute `flow`-binary;
- der komplette bereits veröffentlichte release-root einschließlich `sets/`
  und `current`;
- `release.public.pem`, `desired-state.public.pem` und `control.public.pem`.

nicht übertragen werden `*.private.pem`, SSH-private-keys, das übrige
`FLOW_HOME` oder lab-secrets. prüfen sie auf dem serving-host vor der
installation die binary- und release-digests gegen die werte des
operator-rechners.

führen sie für dieses serving-home **kein** `flow init` aus: der befehl würde
dort neue private signing-/control-keys erzeugen. `start serving` braucht nur
die drei expliziten public-key-dateien und legt seinen privaten lokalen
referenz-state selbst an.

auf einem neuen serving-host werden binary, public keys und release-root in
root-eigenen staging-pfaden bereitgestellt. anschließend:

```sh
sudo install -o root -g root -m 0755 /ABS/STAGE/flow /usr/local/bin/flow
sudo install -d -o root -g root -m 0755 /var/lib/dynamicflow-serving/releases
sudo cp -a --no-preserve=ownership \
  /ABS/STAGE/releases/. /var/lib/dynamicflow-serving/releases/

sudo /usr/local/bin/flow \
  --home /var/lib/dynamicflow-serving-operator \
  start serving --plan \
  --public-url https://serving.example:8443 \
  --listen 0.0.0.0:8443 \
  --service-user dynamicflow-serving \
  --release-public-key /ABS/STAGE/release.public.pem \
  --desired-public-key /ABS/STAGE/desired-state.public.pem \
  --control-public-key /ABS/STAGE/control.public.pem

sudo /usr/local/bin/flow \
  --home /var/lib/dynamicflow-serving-operator \
  start serving \
  --public-url https://serving.example:8443 \
  --listen 0.0.0.0:8443 \
  --service-user dynamicflow-serving \
  --release-public-key /ABS/STAGE/release.public.pem \
  --desired-public-key /ABS/STAGE/desired-state.public.pem \
  --control-public-key /ABS/STAGE/control.public.pem
```

der release-root muss als eigener unterbaum innerhalb des state-roots liegen
und bereits ein gültiges `current` besitzen. er darf weder mit dem state-root
identisch sein noch unter `private/`, `trust/` oder `tls/` liegen oder mit
`config.json` beziehungsweise `bootstrap.sh` kollidieren. der mutierende lauf verlangt UID 0 sowie eine root-eigene,
nicht gruppen-/welt-schreibbare `flow`-binary. er erzeugt beziehungsweise
erhält eine serving-only TLS-identität, kopiert nur public keys, erzeugt den
releasegebundenen bootstrap und gleicht den gehärteten systemd-dienst ab. ein
zweiter identischer lauf ist idempotent und ersetzt weder signing-keys noch
eine vorhandene TLS-identität.

die dateirechte sind teil des sollzustands und werden bei jedem reconcile
erneut geprüft:

- state-root: `0751`, `root:dynamicflow-serving`; für andere benutzer besteht
  nur traverse-recht, kein listing;
- release-root und `sets/`: `0755`, eigentümer
  `dynamicflow-serving:dynamicflow-serving`; `.imports/` bleibt `0700`, der
  einzelne `.publish.lock` `0600`;
- `trust/`: `0755`, `root:dynamicflow-serving`; die drei ausschließlich
  öffentlichen PEM-dateien sind `0644`, damit ein nichtprivilegierter
  `--plan` sie zusammen mit den signierten sets erneut prüfen kann;
- `private/`: `0700` im eigentum des dienstkontos; `tls/` bleibt
  `0750 root:dynamicflow-serving`, TLS-private-key, bootstrap und config
  bleiben `0640 root:dynamicflow-serving`.

nur `private/` und der release-root sind in der ansonsten read-only
systemd-sandbox schreibbar. das traverse-recht am state-root macht weder
private-state noch TLS-key oder config für andere benutzer lesbar.

der erfolgreiche lauf speichert state- und release-root, endpoint,
dienstbenutzer und die drei absoluten public-key-quellen in
`<FLOW_HOME>/serving/local.json` (schema 2). die dateien unter `/ABS/STAGE`
müssen daher root-eigen und dauerhaft verfügbar bleiben. alternativ binden sie
direkt danach die von `flow` kopierten dateien dauerhaft ein:

```sh
sudo /usr/local/bin/flow \
  --home /var/lib/dynamicflow-serving-operator \
  start serving \
  --release-public-key /var/lib/dynamicflow-serving/trust/release.public.pem \
  --desired-public-key /var/lib/dynamicflow-serving/trust/desired-state.public.pem \
  --control-public-key /var/lib/dynamicflow-serving/trust/control.public.pem
```

dieser zweite, idempotente lauf aktualisiert die referenz; danach genügt
`start serving --plan` beziehungsweise `start serving` ohne erneute flags.

lokale kontrolle auf dem serving-host verwendet dasselbe `--home`:

```sh
sudo /usr/local/bin/flow --home /var/lib/dynamicflow-serving-operator status serving
sudo /usr/local/bin/flow --home /var/lib/dynamicflow-serving-operator logs serving --lines 200
```

cloud-firewall, DNS und provider-accounts werden von `flow` nicht geändert.
öffnen oder ändern sie sie nur mit gesonderter freigabe.

## 4. operator an serving pinnen

kopieren sie das öffentliche zertifikat
`/var/lib/dynamicflow-serving/tls/serving.crt` über den bereits
authentisierten bootstrap-kanal zum operator. übernehmen sie den von
`flow start serving` ausgegebenen `SHA256:...`-pin ebenfalls über diesen kanal.

auf dem operator:

```sh
flow serving configure \
  --url https://serving.example:8443 \
  --ca-file /ABS/PATH/serving.crt \
  --tls-pin SHA256:BASE64
flow serving show
```

`configure` prüft CA und exakten leaf-pin, die drei key-ids sowie das aktive
signierte release. redirects und proxy-umgebungsvariablen werden nicht als
fallback benutzt.

### Folge-releases über gepinntes HTTPS veröffentlichen

nach erfolgreichem `flow serving configure` ist der remote-pfad der standard:

```sh
flow release build --rebuild --generation NEXT_MONOTONE_GENERATION
flow release verify
flow release publish --plan
flow release publish
```

`flow release publish --remote` erzwingt den remote-modus und bricht ab, wenn
keine gültige gepinnte serving-bindung vorhanden ist. `--root /ABS/PATH` bleibt
der ausdrücklich lokale modus; `--remote` und `--root` sind gegenseitig
ausgeschlossen.

der plan ist kein kosmetischer dry-run: lokal liest er den retained
release-/history-katalog ohne änderungen; remote authentisiert der control-key
einen read-only manifest-preflight. eine bereits mit anderen bytes belegte
`Komponente/Version/Target`-koordinate oder eine niedrigere generation wird so
vor dem bundle-upload gemeldet. der echte publish prüft dieselbe policy erneut.
jede byteänderung erfordert eine neue komponentenversion; die privaten
operator-manifeste unter `<FLOW_HOME>/releases/manifest-history/` und die
serving-tombstones unter `<release-root>/history/` dürfen nicht gelöscht
werden. der owner-only checkpoint
`<FLOW_HOME>/releases/manifest-history.index.json` bindet zusätzlich die
vollständige set-liste und höchste generation. stage und kanonischer
manifestexport müssen exakt übereinstimmen; andernfalls blockieren verify und
publish bis zum nächsten erfolgreichen build.

die rollen bleiben kryptografisch getrennt: der release-signing-key signiert
das manifest und verlässt den operator nie. der unabhängige control-key
signiert den SHA-256-digest des kanonischen streaming-bundles und autorisiert
genau den import-endpunkt; auch sein private key bleibt lokal. serving erhält
nur die public keys, liest das bundle über gepinntes HTTPS, verifiziert
release-signatur, bundlegröße sowie alle signierten artefaktgrößen und -digests
erneut und schaltet erst danach den atomaren `current`-zeiger um.

client und serving begrenzen den einzelnen upload auf zwei stunden. bei einem
transportfehler kann der ausgang unbekannt sein, etwa wenn nur die antwort auf
eine erfolgreiche aktivierung verloren ging. prüfen sie den serving-status und
wiederholen sie exakt dasselbe set idempotent. eine niedrigere generation oder
dieselbe generation mit anderem inhalt wird abgewiesen. der lokale
release-high-water-mark wird auch bei unklarem oder zurückliegendem
serving-zustand niemals heruntergestuft.

## 5. enrollment erstellen

```sh
flow enroll create \
  --name pbp-01 \
  --profile pbp \
  --host 192.0.2.20 \
  --ssh-user admin \
  --ttl 15m
```

standardmäßig wird ein eigener lokaler Ed25519-SSH-key namens `pbp-01`
erzeugt. nur sein public key steht im signierten desired state. mit
`--key NAME` kann bewusst ein vorhandener operator-key gewählt werden; der
standard hat die kleinere schadensreichweite.

enrollment-ID und secret werden einmal gemeinsam angezeigt. die öffentliche
enrollment-ID und ihre ablaufzeit bleiben als lokale metadaten gespeichert;
das secret wird weder lokal noch auf serving im klartext gespeichert und kann
nicht erneut angezeigt werden. behandeln sie die einmalige ausgabe trotzdem
insgesamt wie ein secret: keine terminalaufzeichnung, kein ticket, kein chat,
kein screenshot. der code ist an name und profil gebunden und standardmäßig
15 minuten gültig.

## 6A. bequemer curl-quickstart

auf der richtigen ziel-VM als der vorgesehene, vorhandene, unprivilegierte
sudo-administrator:

```sh
curl --fail --silent --show-error --insecure \
  https://serving.example:8443/bootstrap | sudo sh
```

der bootstrap akzeptiert als administrator ausschließlich den sicheren,
unprivilegierten `SUDO_USER`. start aus einer reinen root-providerkonsole wird
fail-closed abgelehnt; legen sie dort zuerst den vorgesehenen sudo-admin an und
starten sie den befehl aus dessen sitzung. `root` und `malwarelab` sind keine
zulässigen admin-user.

`flow` fragt in der TTY nach instanzname, profil, enrollment-ID und secret; ID
und secret werden nicht angezeigt. für PBP fragt der feste installer später
die mullvad-accountnummer ebenfalls verdeckt ab. geben sie keine dieser daten
als shellargument oder umgebungsvariable an.

noch vor dem lesen dieser vier enrollment-felder installiert der bootstrap
den festen `dynamicflow-instance-reconcile.timer`. schlägt dessen sicherer
systemd-/binary-preflight fehl, wird kein enrollment-secret gelesen oder
verbraucht. bis `runtime-config.json` atomar committed ist, hält
`ConditionPathExists` den one-shot inert. nach erfolgreichem enrollment zieht
der timer ausschließlich signierten desired state über ausgehendes HTTPS.

ein neueres release aktualisiert auch die target-`flow`-binary selbst. die
erste planphase prüft das exakte `linux-amd64`- beziehungsweise
`linux-arm64`-artefakt, bewahrt die bisher laufende binary root-only und
content-addressed unter
`/var/lib/dynamicflow/instance/apply/runtime-recovery/` und ersetzt
`/usr/local/bin/flow` atomar. die alte invocation stoppt anschließend vor
allen profilphasen und vor dem checkpoint. der nächste timerlauf startet den
festen neuen pfad und setzt idempotent fort; ein zwischenzeitlicher status
`applying` mit `runtime_handoff=true` ist deshalb erwartet und noch kein
vollständig angewandtes profil.

### Ehrliche vertrauensgrenze

`--insecure` ist hier absichtlich sichtbar: die ersten bootstrap-bytes werden
vollständig dem adressierten serving/TLS-pfad vertraut. ein angreifer, der
diesen erstdownload ersetzt, führt code als root aus. der
`X-Dynamicflow-Bootstrap-SHA256`-header derselben antwort ist kein unabhängiger
beweis. erst das authentisierte script pinnt CA, zertifikat, release-key,
desired-state-key und den im signierten manifest gebundenen `flow`-digest.

dieser weg eignet sich nur, wenn providerkonsole, zieladresse und serving-netz
bereits als ausreichender bootstrap-trust gelten.

## 6B. gehärtet: download, unabhängig prüfen, ausführen

ermitteln sie auf der vertrauenswürdigen serving-konsole den digest:

```sh
sudo sha256sum /var/lib/dynamicflow-serving/bootstrap.sh
```

übertragen sie diesen wert und `serving.crt` über einen **anderen
authentisierten kanal** zur ziel-VM. dann als unprivilegierter sudo-admin:

```sh
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --cacert /ABS/PATH/serving.crt \
  https://serving.example:8443/bootstrap \
  -o "$tmp_dir/bootstrap.sh"

printf '%s  %s\n' EXPECTED_HEX_SHA256 "$tmp_dir/bootstrap.sh" \
  | sha256sum --check --strict -
chmod 0700 "$tmp_dir/bootstrap.sh"
sudo sh "$tmp_dir/bootstrap.sh"
```

ersetzen sie `EXPECTED_HEX_SHA256` nur lokal mit dem unabhängig erhaltenen
wert. schreiben sie enrollment- oder mullvad-secrets nicht in dieses script.
der digest ändert sich, wenn serving einen bootstrap für ein neues release
erzeugt; prüfen sie ihn dann erneut out-of-band.

noch stärker ist eine bereits über ein vertrauenswürdiges image installierte
`flow`-binary zusammen mit separat provisionierten CA-/signing-pins; dann ist
kein remote geladenes shellscript teil der vertrauensbasis.

## 7. hostkey unabhängig pinnen, dann status und zugriff

exportieren sie die einzelne öffentliche datei
`/etc/ssh/ssh_host_ed25519_key.pub` über die authentisierte providerkonsole zum
operator und vergleichen sie ihren Ed25519-fingerprint dort out-of-band.
verwenden sie weder serving-status noch `ssh-keyscan` als quelle. falls der
SSH-endpunkt nicht schon beim enrollment gebunden wurde:

die lokale exportdatei ist zwar öffentlich, aber trust-relevant: als reguläre,
nicht verlinkte datei mit modus `0600` ablegen und nach dem pin vor
unbeabsichtigtem austausch schützen.

```sh
flow instance bind pbp-01 --host 192.0.2.20 --ssh-user admin
```

pinnen sie danach die geprüfte datei. der befehl stellt keine
netzwerkverbindung her:

```sh
flow instance hostkey pin pbp-01 \
  --public-key-file /ABS/PATH/ssh_host_ed25519_key.pub
```

erst jetzt status abrufen und zugriff testen:

```sh
flow --json instance status pbp-01
flow instance list
```

`status` übernimmt niemals einen ersten hostkey. er zeigt den von der instanz
gemeldeten fingerprint nur als beobachtung und vergleicht ihn mit dem bereits
lokal gepinnten key. bei abweichung stoppt `flow` fail-closed; folgen sie dem
[hostkey-recovery](RECOVERY-RUNBOOK.md#ssh-hostkey-hat-sich-geändert).

```sh
flow instance ssh pbp-01
flow instance ssh pbp-01 --gui --local-port 5901
```

der GUI-befehl öffnet nur den SSH-tunnel. ein VNC-client verbindet lokal zu
`127.0.0.1:5901`; port 5901 darf in keiner cloud-firewall öffentlich sein.

## 8. freigabestatus kontrollieren

```sh
flow instance status pbp-01
flow instance logs pbp-01
flow test lab --inventory /ABS/PATH/.flow/lab.yaml --plan
```

ein `ready`-status ist noch kein PBP-soak-nachweis. produktionsfreigabe setzt
den vollständigen ablauf aus dem [lab-/E2E-runbook](LAB-E2E-RUNBOOK.md) und
einen realen mindestens 30-minütigen PBP-lauf voraus.
