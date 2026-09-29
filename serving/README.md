# Dynamicflow serving und historischer toolkit-downloadserver

> **migrationshinweis:** die als historisch markierten abschnitte beschreiben
> den älteren toolkit-downloadserver und sind nicht der normale
> dynamicflow-operatorpfad. die aktuelle serving-rolle wird mit
> `flow start serving [--plan]`, `flow status serving`, `flow logs serving`
> sowie `flow release publish` verwaltet. direkte aufrufe der legacy-skripte
> sind nur für komponentenentwicklung, initialen transport oder ausdrücklich
> dokumentierte recovery-arbeit vorgesehen.

## Aktueller dynamicflow-serving-pfad

der aktuelle operatorpfad baut und verifiziert ein vollständiges, signiertes
release-set und veröffentlicht es nach dem erstbootstrap über gepinntes HTTPS:

```sh
flow release build --rebuild
flow release verify
flow release publish --plan
flow release publish
```

`flow start serving --plan` prüft den gewünschten zustand ohne mutation; der
anschließende explizite `flow start serving` gleicht dienst, TLS-identität,
public trust und aktiven release-root idempotent ab. die vollständige
erstbootstrap-syntax und vertrauensgrenze stehen im
[quickstart](../docs/QUICKSTART.md), der laufende betrieb im
[operator-runbook](../docs/OPERATOR-RUNBOOK.md).

der release-root ist ein strikt separater unterbaum des state-roots. der
state-root ist `0751 root:dynamicflow-serving`, der release-root sowie
`sets/` und die signaturverifizierte manifest-historie `history/` sind
`0755 dynamicflow-serving:dynamicflow-serving`, `.imports/` ist `0700` und der
publish-lock `0600`. die tombstones unter `history/` erhalten generation- und
versionsbindungen nach auditiertem artefakt-pruning und dürfen nicht gelöscht
werden. `trust/` und die drei öffentlichen PEM-dateien sind
`0755` beziehungsweise `0644` im eigentum `root:dynamicflow-serving`;
`private/` bleibt dienstkontrolliert `0700`, `tls/`
`0750 root:dynamicflow-serving` und TLS-key, bootstrap sowie config bleiben
`0640 root:dynamicflow-serving`. serving verteilt bootstrap, desired
state und unveränderliche sets ausschließlich über HTTPS und initiiert niemals
SSH zu ziel-vms.

alle folgenden downloadpasswort-/TOTP-, `serving/current`-, `install.sh`- und
shell-publisher-abläufe dokumentieren ausschließlich den historischen
toolkit-pfad. sie dürfen weder mit dem aktuellen signierten release-root
vermischt noch als aktueller produktions- oder E2E-nachweis verwendet werden.

## Historischer toolkit-release-set und passwörter (stand: 2026-07-15)

`serving` ist ab diesem stand die einzige quelle, aus der provisioniert wird.
arbeitsverzeichnisse wie `dynamicflow/ssh`, `dynamicflow/vpn`, `dynamicflow/pbp`,
`dynamicflow/decepticon` werden während einer
serverbereitstellung nie direkt gelesen.

die lokale struktur ist:

```text
sources/<tool>/<version>/...                 geprüfter Quellsnapshot
releases/<tool>/<version>/<target>/...      unveränderliche Artefakte
sets/<set-id>/release-set.tsv                vollständiger, gehashter Stand
current -> sets/<set-id>                     freigegebener lokaler Set
```

nur wenn sich toolquellen bewusst geändert haben, wird ein neuer set gebaut:

```sh
cd ~/Projects/dynamicflow/serving
./snapshot-current-tools.sh
```

der builder übernimmt ausschließlich allowlistete dateien, führt die jeweiligen
tests aus, baut SSH/GUI, VPN, beide PBP-architekturen und decepticon reproduzierbar und
verweigert geänderte bytes unter derselben version. der aktuelle
decepticon-kandidat `v0.3.1-validation.6` wird aus einem sauberen git-stand
gebaut, bleibt wegen seines prerelease-namens aber bewusst im kanal `validation`.
examstation ist bewusst nicht bestandteil dieses standard-release-sets und wird bei der serverprovisionierung nicht gebaut oder veröffentlicht.

`./provision-server.sh` prüft `current` vor dem ersten remote-umbau und
veröffentlicht nach caddy/MFA und `install.sh` automatisch den gesamten set.
ein manueller publish auf einen vorhandenen host lautet:

```sh
TOOLKIT_SSH_HOST=SERVER_IP \
TOOLKIT_SSH_IDENTITY="$HOME/.ssh/toolkit-serving-download" \
TOOLKIT_PUBLIC_BASE_URL=https://SERVER_IP \
  ./publish-release-set.sh
```

der curl-dialog verlangt **nicht** das admin-passwort. er verlangt das beim
MFA-enrollment einmal angezeigte download-passwort für benutzer `toolkit` und
danach einen frischen sechsstelligen TOTP-code. SSH-administration ist key-only.
der provisionierer erzeugt zusätzlich automatisch einen getrennten
Ed25519-deploy-key unter `~/.ssh/toolkit-serving-download`; der admin-key ist
beim benutzer `download` nicht mehr gültig.

der host speichert beim ersten MFA-setup eine feste deadline und prüft sie jede
minute. standardmäßig fährt er nach 24 stunden herunter; erneutes MFA-enrollment
setzt die deadline nicht zurück. das begrenzt die netzwerk-laufzeit
hostseitig, ersetzt aber keine AWS-terminierung: die instanz und ihr
unverschlüsseltes volume müssen danach providerseitig gelöscht und durch einen
neuen host mit neuen MFA-/SSH-secrets ersetzt werden. download-bearer gelten
weiterhin nur zehn minuten.


## Decepticon: installations-einzeiler

auf einer frischen debian-/ubuntu-VM lädt, prüft und bootstrapt dieser befehl
die aktuelle veröffentlichte decepticon-version:

```sh
curl -fsSL https://downloads.example.com/install.sh|sh -s -- decepticon
```

der installer fragt das download-passwort und danach einen frischen sechsstelligen
TOTP-code jeweils ohne echo über `/dev/tty` ab. er tauscht beide faktoren einmal
gegen einen zufälligen, zehn minuten gültigen und an die quell-IP gebundenen
download-token. danach lädt er `latest.txt`, prüft manifest und artefakt,
entpackt atomar und startet `bootstrap-decepticon-vm.sh` automatisch.

der bootstrap startet zuerst den im datapack geprüften `setup-mullvad.sh` im
vordergrund. nach dem toolkit-passwort wird die mullvad-accountnummer separat und
verdeckt über `/dev/tty` abgefragt. sie wird ausschließlich per stdin an die
mullvad-CLI übergeben und erscheint weder in prozessargumenten noch im log.
das setup verbindet mullvad über shadowsocks auf port 443 und aktiviert
auto-connect sowie lockdown.

sobald der tunnel verifiziert ist, läuft der weitere decepticon-bootstrap. die
interaktive statuszeile folgt den tatsächlich erreichten phasen system, docker,
source, runtime, launcher, container-images und mullvad-egress und zeigt den
jeweils aktiven schritt statt erfundener prozentwerte. die vollständige ausgabe
bleibt mit modus `0600` unter
`~/.local/share/toolkit/decepticon/logs/` erhalten. mit
`TOOLKIT_PROGRESS=verbose` lässt sich für eine diagnose wieder die komplette
live-ausgabe einschalten.

vor der ersten interaktiven phase prüft der installer die benötigten
sudo-rechte. auf cloud-vms mit passwordless sudo läuft das ohne nachfrage;
andernfalls erscheint der sudo-passwortdialog einmal sichtbar. nichtinteraktive
installationen benötigen passwordless sudo.

danach läuft der gesamte normale IPv4-egress des hosts über mullvad. nach dem
image-build wird zusätzlich der egress aus dem gebauten sandbox-container
verifiziert. IPv6 ist auf host- und tunnelebene deaktiviert; lockdown blockiert
normalen egress bei einem tunnelabbruch fail-closed. einzige bewusste
routing-ausnahme ist der effektive SSH-port, damit die management-verbindung
außerhalb des tunnels erreichbar bleibt; dadurch wird kein zusätzlicher port
eingehend geöffnet. beim ersten lauf die providerkonsole und die bestehende
IPv4-SSH-sitzung bis zum frischen SSH-, container- und neustarttest offen halten.

der launcher wird nach `/usr/local/bin/decepticon` installiert und verwendet
automatisch `~/.decepticon`. deshalb sind direkt nach erfolgreichem bootstrap
weder ein `export PATH=...` noch ein `DECEPTICON_HOME=...` nötig. onboarding
und stack-start bleiben bewusst separat, weil sie interaktive konfiguration
benötigen:

```sh
decepticon onboard --reset
decepticon start
```

eine validierungs- oder produktionsversion lässt sich fest pinnen:

```sh
curl -fsSL https://downloads.example.com/install.sh|sh -s -- decepticon v0.3.1-validation.6
```

wenn docker gerade neu installiert und der benutzer zur docker-gruppe
hinzugefügt wurde, kann der bootstrap kontrolliert zum erneuten login
auffordern. der installer druckt dafür einen auf die bereits geprüfte version
gepinnten wiederholungsbefehl. nach dem erneuten SSH-login diesen befehl
ausführen; die immutable version wird wiederverwendet und `current` erst nach
erfolgreichem bootstrap aktiviert.

nur herunterladen, prüfen und aktivieren, aber nicht bootstrappen:

```sh
TOOLKIT_INSTALL_ONLY=1 sh -c 'curl -fsSL https://downloads.example.com/install.sh|sh -s -- decepticon'
```

## Mullvad VPN: einzeiler

auf einer frischen debian-12+/ubuntu-24.04+-VM mit systemd, amd64/arm64 und
einem normalen sudo-fähigen SSH-administrator installiert dieser befehl
firefox sowie das offizielle mullvad-paket, meldet die VM an und verbindet
mullvad über shadowsocks auf port 443:

```sh
curl -fsSL https://downloads.example.com/install.sh|sh -s -- vpn
```

zuerst wird verdeckt das toolkit-download-passwort abgefragt, danach separat die
mullvad-accountnummer. die accountnummer wird nur per stdin an die mullvad-CLI
gegeben und erscheint weder in prozessargumenten noch in logs.
der einzeiler wird als normaler SSH-administrator, beispielsweise `ubuntu`,
und ohne vorangestelltes `sudo` gestartet; der bootstrap übernimmt den
root-wechsel selbst. er muss aus einer IPv4-SSH-sitzung gestartet werden und
schaltet IPv6 anschließend systemweit sowie im mullvad-tunnel ab.

vor dem connect installiert der bootstrap mullvads offizielle nftables-
ausnahme ausschließlich für die effektiven SSH-ports. VNC bleibt auf
`127.0.0.1:5901` und läuft durch diesen SSH-tunnel; port 5901 und port 443
werden nicht eingehend geöffnet. ein systemd-rollback-timer schützt den ersten
connect. nach verifiziertem shadowsocks-, IPv4- und benutzer-egress
werden lockdown und auto-connect aktiviert. trotzdem beim ersten lauf die
providerkonsole offen lassen und danach frisches SSH, VNC und einen neustart
testen.

firefox nutzt ohne browserproxy das mullvad-systemrouting. DNS-over-HTTPS und
WebRTC werden systemweit gesperrt ausgeschaltet. der mullvad-management-socket
und `mullvad-exclude` sind auf sudo/root beschränkt, damit `malwarelab` und
normale benutzerprozesse weder die accountnummer lesen noch den VPN umgehen.

vor dem löschen einer wegwerf-VM `sudo mullvad disconnect --wait` und danach
`sudo mullvad account logout >/dev/null` ausführen und zehn sekunden warten;
andernfalls bleibt einer der mullvad-geräteplätze belegt.

VPN wird nicht einzeln veröffentlicht. `snapshot-current-tools.sh` baut und
prüft den VPN-block zusammen mit den übrigen tool-blöcken; anschließend wird
der vollständige release-set atomar veröffentlicht.

## PBP: deutscher mullvad-ausgang mit windows-firefox-persona

PBP wird nach `ssh-gui-hardening` auf einer frischen debian-/ubuntu-VM
ausgeführt. beide aliase installieren dasselbe kanonische tool `pbp`:

```sh
curl -fsSL https://downloads.example.com/install.sh | sh -s -- --PBP
curl -fsSL https://downloads.example.com/install.sh | sh -s -- pbp
```

der host bleibt linux. PBP verwendet camoufox nur für eine vollständige
windows-firefox-persona und hält diese innerhalb der wegwerf-VM stabil.
mullvad wird vorher auf deutschland, shadowsocks port 443, auto-connect und
lockdown festgelegt. browserseitig gibt es keinen proxy; der launcher prüft
vor jedem sichtbaren, interaktiven start erneut einen deutschen
mullvad-ausgang. playwright verwaltet nur den prozess-lebenszyklus und führt
keine seitenautomation aus.

der PBP-build liefert getrennte `linux-amd64/pbp.tar.gz`- und
`linux-arm64/pbp.tar.gz`-artefakte. browser, uBlock origin und jede
python-abhängigkeit sind versioniert und gehasht; der VM-bootstrap lädt keine
mutable `latest`-browserdatei. eine perfekte oder „100 prozent“
fingerprint-garantie wird bewusst nicht behauptet. das lokale gate prüft
stattdessen persona-konsistenz, germany-egress und fail-closed-start.

PBP `v0.1.7` ist im versiegelten release-set für `linux-amd64` und
`linux-arm64` enthalten und wird durch die serverprovisionierung gemeinsam mit
den anderen tools veröffentlicht.

## Examstation: nur bewusst manuell veröffentlichen

examstation läuft auf einer eigenen debian-13-VM und ist absichtlich nicht teil von `serving/current`. `provision-server.sh`, `snapshot-current-tools.sh` und `publish-release-set.sh` nehmen sie daher nicht automatisch mit.

der separate release wird im verzeichnis `dynamicflow/examstation` gebaut. der bestehende `install.sh examstation ...`-pfad bleibt ausschließlich für eine spätere, ausdrücklich manuell veröffentlichte examstation-version erhalten; ohne diesen bewussten einzel-publish ist examstation auf einem frisch provisionierten downloadserver nicht verfügbar.

## Zweck und aktueller freigabestatus

der server stellt den öffentlichen bootstrap-installer und private,
versionierte tool-artefakte unter `https://downloads.example.com` bereit.

die lokale build-, publish- und installationskette ist getestet. vor einem
produktiv-publish fehlen noch zwei bewusste freigabeschritte:

1. die custom-decepticon-änderungen committen und mit einem nachvollziehbaren
   tag versehen. der produktions-publisher verweigert einen schmutzigen
   checkout.
2. den veröffentlichten kandidaten auf einer frischen debian-13-VM inklusive
   bootstrap und docker-start testen.

vor einer veröffentlichung muss der vollständige release-set in einer eigenen testumgebung geprüft werden.

## Sicherheitsmodell

- öffentlich: `/health.txt` und `/install.sh`
- passwort plus TOTP: `/tools/*`
- alles andere: HTTP 404
- tokens sind zufällig, zehn minuten gültig und an die quell-IP gebunden.
- ein TOTP-code ist nur einmal verwendbar.
- drei fehlgeschlagene token-anmeldungen in zehn minuten sperren die IP zunächst eine stunde; wiederholungen verlängern bis auf eine woche.

das passwort wird beim setup erzeugt oder verdeckt eingegeben; caddy speichert nur den Argon2id-hash. das TOTP-geheimnis wird mit systemds host-key als AES-256-GCM-credential verschlüsselt. vor der secret-ausgabe prüft das setup den root-only-host-key sowie einen vollständigen ver- und entschlüsselungs-roundtrip. QR-code und Base32-variante werden nur beim enrollment angezeigt. `.netrc`, klartext-umgebungsvariablen und secrets in prozessargumenten werden nicht verwendet. da host-key und credential auf demselben server liegen, kann root- oder offline-zugriff auf ein unverschlüsseltes root-dateisystem das secret entschlüsseln; stärkeren schutz bieten vollständige datenträgerverschlüsselung beziehungsweise TPM-gebundene credentials.
das setup installiert bewusst das offizielle stabile caddy-paket ab version 2.11.4, prüft den repository-key-fingerprint und validiert die vollständige caddy-konfiguration vor der passwort- und TOTP-ausgabe. das veraltete debian-13-paket 2.6.2 wird nicht verwendet.

### Rollenmodell

- `serving` ist der einzige host, den `provision-server.sh` vom lokalen PC aus einrichtet. er öffnet SSH, 80/tcp und 443/tcp.
- `worker` ist ein download-artefakt für die isolierte decepticon-VM. es lässt docker seine eigenen forward-/egress-regeln verwalten.
- `gui` ist ein download-artefakt für die isolierte GUI/VNC-VM. SSH-forwarding bleibt auf den lokalen VNC-port 5901 begrenzt.

der downloadserver stellt die worker-/GUI-baselines nur bereit; er wird selbst weder worker noch GUI. die vms ziehen die pakete per ausgehendem HTTPS und brauchen keine eingehende verbindung vom lokalen PC.

`prepare` führt das system-upgrade genau einmal aus. `activate` validiert SSH und nftables und startet einen fünfminütigen rollback-timer; erst ein neuer SSH-login bestätigt per `commit`.

lokale komponenten: `remote-debian-hardening.sh`, `provision-server.sh`, `setup-caddy-mfa.sh`, `install.sh`, `snapshot-current-tools.sh`, `verify-release-set.sh`, `publish-release-set.sh`, `deploy-installer.sh` sowie `server/toolkit_auth.py` und der atomare remote-finalizer. details stehen in `PROVISIONING.md`.

## Remote-struktur

```text
/srv/downloads/
  health.txt
  install.sh
  tools/
    index.txt
    ssh/
      latest.txt
      v0.1.6/
        SHA256SUMS
        linux-amd64/
          ssh.tar.gz
    decepticon/
      latest.txt
      v0.3.1/
        SHA256SUMS
        any/
          decepticon.tar.gz
```

die download-version ist die paketversion des servers. sie muss nicht mit der
upstream-decepticon-version identisch sein. jedes decepticon-datapack enthält
`VERSION`, `BUILD_INFO`, prüfsummen und linux-launcher für amd64 und arm64.

## Einmalige downloadserver-einrichtung

vom lokalen PC gibt es genau einen einstieg:

```sh
cd /path/to/dynamicflow/serving
./provision-server.sh
```

der provisionierer ist fest auf `serving` gesetzt. voraussetzungen sind eine frische debian-13-VM, ein provider-SSH-key, eine geöffnete providerkonsole und eine provider-firewall mit SSH, 80/tcp und 443/tcp. der öffentliche HTTPS-host ist standardmäßig die eingegebene server-IP: eine globale IPv4 benötigt kein DNS und erhält automatisch ein öffentlich vertrauenswürdiges, kurzlebiges let's-encrypt-IP-zertifikat. alternativ kann ein korrekt auf den server zeigender DNS-name eingegeben werden. private oder reservierte ips werden abgelehnt.

für den admin-schlüssel ist `~/.ssh/dynamic/` der standard. der
gemeinsame picker listet dort reguläre private key-kandidaten alphabetisch auf,
blendet `.pub`, `authorized_keys`, `known_hosts` und `config` aus und fragt nach
der gewünschten nummer; auswahl `1` ist der standard. derselbe picker läuft bei
direkten `deploy-installer.sh`- und `publish-release-set.sh`-aufrufen, sofern
kein expliziter `TOOLKIT_SSH_IDENTITY`-pfad gesetzt ist. ein anderer
verzeichnis- oder schlüsselpfad kann mit `TOOLKIT_ADMIN_IDENTITY` vorgegeben
werden.

ein lauf erledigt baseline-hardening, sicheren SSH-neulogin mit rollback, getrennten admin-/deploy-key, caddy, MFA, Fail2ban, QR- und Base32-enrollment, den TOTP-test, den festen 24h-deadline-guard, `/health.txt`, `install.sh` und den vollständigen versiegelten release-set. es gibt keine worker-/GUI-auswahl und keine separaten uploadschritte.
wenn hardening und MFA bereits abgeschlossen wurden, aber nur die abschließende HTTPS-prüfung den falschen host verwendete, bleibt die VM bestehen. ein befehl ersetzt das MFA-enrollment, stellt caddy auf die öffentliche IP um und wiederholt deployment plus verifikation:

```sh
./provision-server.sh --finish-existing SERVER_PUBLIC_IP
```

dabei ein neues passwort/TOTP-enrollment speichern und den vorherigen authenticator-eintrag löschen.

worker- und GUI-vms werden danach in ihrer providerkonsole gestartet und ziehen ihre baseline selbst vom downloadserver:

```sh
BASE=https://SERVER_PUBLIC_IP

# Worker-VM: SSH-Baseline, danach Decepticon
curl -fsSL "$BASE/install.sh" | sh -s -- ssh-hardening v0.1.6
curl -fsSL "$BASE/install.sh" | sh -s -- decepticon

# GUI-VM: SSH-/VNC-Baseline
curl -fsSL "$BASE/install.sh" | sh -s -- ssh-gui-hardening v0.1.6
```

im IP-modus setzt das nur ausgehendes HTTPS von der VM zum downloadserver voraus; bei einem DNS-namen zusätzlich DNS. der downloadserver verbindet sich nie in die vms und speichert keine privaten VM-schlüssel. jeder installer-lauf fragt am VM-terminal das download-passwort und einen frischen TOTP-code ab. SSH `v0.1.6`, VPN `v0.2.6`, PBP `v0.1.7` und decepticon `v0.3.1-validation.6` werden beim provisionieren automatisch aus `serving/current` veröffentlicht.

## Installer oder release-set aktualisieren

nur den bereits versiegelten installer mit dem getrennten deploy-key aktualisieren:

```sh
cd /path/to/dynamicflow/serving
HOST=SERVER_PUBLIC_IP
KEY=~/.ssh/toolkit-serving-download

TOOLKIT_SSH_HOST="$HOST" \
TOOLKIT_SSH_PORT=22 \
TOOLKIT_SSH_IDENTITY="$KEY" \
TOOLKIT_PUBLIC_BASE_URL="https://$HOST" \
  ./deploy-installer.sh
```

den vollständigen aktuellen stand atomar veröffentlichen:

```sh
TOOLKIT_SSH_HOST="$HOST" \
TOOLKIT_SSH_PORT=22 \
TOOLKIT_SSH_IDENTITY="$KEY" \
TOOLKIT_PUBLIC_BASE_URL="https://$HOST" \
  ./publish-release-set.sh
```

`publish-release-set.sh` lädt immer genau `serving/current`: alle fünf artefakte werden zuerst vollständig geprüft und gestaged, dann unter einem serverseitigen lock gemeinsam aktiviert. bei einem fehler bleibt der vorherige stand aktiv. provisionierung ruft diesen ablauf automatisch auf.

## Modulgrenze

tool-verzeichnisse bauen ausschließlich lokale artefakte. sie kennen weder
server, deploy-key noch MFA-konfiguration. `snapshot-current-tools.sh` ist die
einzige brücke von den tool-blöcken zum versiegelten gesamtstand;
`publish-release-set.sh` ist die einzige brücke vom gesamtstand zum server.
damit kann kein einzelnes tool den aktiven stand teilweise überschreiben.

decepticon `v0.3.1-validation.6` ist bewusst als `validation` markiert. für produktion ist ein sauberer, getaggter und erneut versiegelter decepticon-build erforderlich.

## Nichtinteraktive installation

automation muss zwei reguläre, dem aufrufenden benutzer gehörende dateien mit modus `0400` oder `0600` bereitstellen. `TOOLKIT_AUTH_FILE` enthält eine zeile `toolkit:PASSWORT`, `TOOLKIT_TOTP_FILE` genau den aktuellen sechsstelligen code. beide werden gemeinsam gesetzt.

```sh
TOOLKIT_AUTH_FILE=/run/secrets/toolkit-auth \
TOOLKIT_TOTP_FILE=/run/secrets/toolkit-totp \
  sh -c "curl -fsSL https://downloads.example.com/install.sh | sh -s -- decepticon"
```

die dateien sollten nur für diesen lauf aus einem secret-store gemountet werden. `TOOLKIT_AUTH`, `TOOLKIT_TOTP` und `.netrc` werden absichtlich abgelehnt. der aktuelle TOTP-code muss unmittelbar vor jedem lauf sicher erzeugt oder bereitgestellt werden.

## Go-live-prüfung

der downloadserver wird nur im `serving`-profil geprüft: zweiter SSH-login samt rollback, HTTP/HTTPS, erfolgreiche TOTP-anmeldung, atomarer gesamt-publish und der ban nach der dritten fehlanmeldung. worker-container-egress und der lokale VNC-tunnel werden getrennt auf den jeweiligen ziel-vms getestet; diese rollen laufen nie auf dem downloadserver.

lokal gelten mindestens: `bash -n ./*.sh tests/*.sh`, `./tests/provision-static-checks.sh`, `./tests/mfa-static-checks.sh`, `python3 -m unittest -v tests/test_toolkit_auth.py`, `./tests/release-flow.sh` und `./tests/release-set-checks.sh`.

## Rollback und betrieb

artefakte werden nicht in-place repariert oder gelöscht. bei einem fehlerhaften
release wird `latest.txt` atomar auf eine bereits geprüfte version
zurückgesetzt; anschließend wird die ursache unter einer neuen versionsnummer
behoben. clients mit bereits aktivierter version können ihren `current`-symlink
auf ein vorhandenes release zurückstellen.

regelmäßig prüfen:

- `systemctl status ssh nftables caddy toolkit-auth fail2ban unattended-upgrades --no-pager`
- `nft list ruleset`, `fail2ban-client status toolkit-mfa` und die provider-firewall
- ablauf/erneuerung des TLS-zertifikats in den caddy-logs
- freien speicher, root-login-alarme und backups von `/srv/downloads`
- ob nur erwartete immutable versionen vorhanden sind

eine versehentlich gesperrte adresse wird über SSH mit `sudo fail2ban-client set toolkit-mfa unbanip CLIENT_IP` entsperrt.

noch offen vor der ersten produktionsfreigabe sind der frische VM-smoke-test
und eine bewusste entscheidung über zusätzliche artefaktsignaturen. SHA-256
schützt die übertragung gegen beschädigung; eine separate signatur würde auch
die provenienz unabhängig vom download-server absichern.
