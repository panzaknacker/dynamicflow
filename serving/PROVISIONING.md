# Einrichtung des Toolkit-Download-Servers

> **alt-/komponentendokument:** dieses runbook beschreibt den älteren
> provisioner für den toolkit-download-server und die migrationswerkzeuge. es
> ist nicht der normale dynamicflow-betriebsablauf. für die aktuelle
> serving-rolle `flow start serving [--plan]`, `flow status serving`,
> `flow logs serving` und `flow release publish` verwenden. die folgenden
> shell-skripte nur für komponentenentwicklung, den ersten transport oder
> ausdrücklich dokumentierte recovery-arbeit aufrufen.

`provision-server.sh` richtet genau einen frischen debian-13-download-/serving-host
über SSH ein. es richtet nie worker- oder GUI-VMs ein und kontaktiert sie
nicht. die provider-konsole und die ursprüngliche SSH-sitzung offen lassen, bis
das skript `HARDENING_OK` ausgibt.

```sh
./provision-server.sh
```

die abfrage des öffentlichen HTTPS-hosts verwendet standardmäßig den SSH-host.
ein DNS-name nutzt normale ACME-zertifikate. eine global routbare IPv4-adresse
braucht kein DNS; caddy fordert ausdrücklich das profil `shortlived` von let's
encrypt an und erneuert sein öffentlich vertrauenswürdiges IP-zertifikat mit
etwa sechs tagen laufzeit automatisch. private, loopback- und reservierte
IPv4-adressen werden abgelehnt.

wenn härtung und MFA abgeschlossen sind, die abschließende öffentliche prüfung
aber den falschen host verwendet hat, den bestehenden server behalten und einen
befehl ausführen. er ersetzt die MFA-registrierung, stellt caddy auf den
gewünschten öffentlichen host um, stellt den installer erneut bereit und prüft
HTTPS:

```sh
./provision-server.sh --finish-existing 203.0.113.10
```

statt der dokumentationsadresse die tatsächliche global routbare IPv4-adresse
des servers verwenden. der provisioner ist auf die policy `serving` festgelegt:
SSH sowie 80/tcp und 443/tcp sind erreichbar, TCP-forwarding ist deaktiviert,
und der host betreibt weder decepticon noch docker-workloads, GUI oder VNC.

das skript legt einen administrator nur mit schlüsselanmeldung und ein
passwortgesperrtes deploy-konto `download` ohne sudo an. es erzeugt automatisch
einen separaten lokalen Ed25519-deploy-schlüssel unter
`~/.ssh/toolkit-serving-download` oder verwendet ihn wieder, installiert diesen
öffentlichen schlüssel mit OpenSSH `restrict` und entfernt den admin-schlüssel
aus dem deploy-konto. es führt das upgrade einmal aus, prüft passwortloses sudo,
aktiviert SSH/sysctl/nftables mit einem rollback nach fünf minuten, prüft eine
frische anmeldung und installiert dann caddy, MFA und Fail2ban. zum schluss
legt es `/health.txt` an, stellt das öffentliche `install.sh` bereit und
veröffentlicht atomar jedes artefakt aus dem bereits geprüften release-set
`serving/current`.

caddy wird aus seinem offiziellen stabilen repository installiert, dessen
OpenPGP-fingerprint gepinnt ist. versionen älter als 2.11.4 werden abgelehnt.
bevor ein passwort oder TOTP-secret angezeigt wird, prüft das setup die
vollständige caddyfile und testet einen hin- und rückweg für ein
systemd-credential, das mit dem nur für root lesbaren host-schlüssel
verschlüsselt ist. der host-key-modus schützt die credential-datei, aber nicht
gegen root oder offline-zugriff auf dasselbe unverschlüsselte
root-dateisystem; für dieses bedrohungsmodell festplattenverschlüsselung oder
TPM-gebundene credentials verwenden.

die private `.pem`-datei des providers bleibt auf dem lokalen PC, muss eine
reguläre datei sein und wird auf modus `0600` gesetzt. nur der daraus
abgeleitete öffentliche schlüssel wird in das temporäre entfernte
staging-verzeichnis kopiert. der download-server erhält nie private schlüssel
für worker- oder GUI-VMs.

## Pull-Modell für VMs

worker und GUI sind release-artefakte unter `/srv/downloads/tools`, keine
auswählbaren profile des download-servers. eine isolierte VM startet über ihre
provider-konsole und braucht im IP-modus nur ausgehenden HTTPS-zugang zum
download-server (bei verwendung eines DNS-namens zusätzlich DNS):

```sh
BASE=https://SERVER_PUBLIC_IP

# Worker VM
curl -fsSL "$BASE/install.sh" | sh -s -- ssh-hardening v0.1.2
curl -fsSL "$BASE/install.sh" | sh -s -- decepticon

# GUI/VNC VM
curl -fsSL "$BASE/install.sh" | sh -s -- ssh-gui-hardening v0.1.2
```

jeder aufruf fragt auf `/dev/tty` nach dem erzeugten MFA-download-passwort für
den benutzer `toolkit` (nicht dem SSH-admin-passwort) und einem frischen
TOTP-code. kein secret landet in der URL, der befehlszeile, der umgebung oder in
`.netrc`. das daraus entstehende kurzlebige bearer-token ist an die quell-IP
gebunden.

der worker-bootstrap darf keine konkurrierende nftables-basis-chain `forward`
installieren; docker bleibt für container-forwarding und egress zuständig. der
GUI-bootstrap erlaubt nur lokales SSH-forwarding zum loopback-VNC-port 5901.
docker-DNS-/HTTPS-egress und den VNC-tunnel nach der installation und nach einem
neustart prüfen.

ein neuer download-server erhält genau das versiegelte lokale set `current`:
SSH/GUI, VPN, beide PBP-architekturen und decepticon. examstation ist bewusst
aus der standardeinrichtung ausgenommen und muss bei ausdrücklichem bedarf
separat gebaut und veröffentlicht werden. die einrichtung baut nie aus
benachbarten arbeitsbäumen und führt diese werkzeuge nie auf dem serving-host
aus. wenn sich werkzeugquellen absichtlich ändern, zuerst
`./snapshot-current-tools.sh` ausführen; es testet quellen aus der allowlist,
erstellt einen snapshot und verweigert abweichende bytes unter einer bereits
bestehenden version.

die erste MFA-einrichtung speichert außerdem eine feste host-frist von 24
stunden. `toolkit-expire.timer` prüft sie jede minute und schaltet den gast bei
erreichen ab; eine erneute MFA-einrichtung verlängert sie nicht. das ist eine
absicherung auf host-seite, keine löschung in der cloud. nach dem lauf die
AWS-instanz beenden und ihr volume löschen, dann auf dem ersatz-host frische
MFA- und SSH-schlüssel einrichten.
