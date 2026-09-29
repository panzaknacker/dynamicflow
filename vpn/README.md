# Toolkit VPN + firefox

> **legacy-/komponentendokument:** die folgenden toolkit-einzeiler und
> shell-installer sind interne übergangs- und komponentenwerkzeuge. sie sind
> kein normaler operator-einstieg. neue installationen verwenden `flow`, ein
> signiertes profil und den ausgehenden HTTPS-reconcile; siehe `flow --help`
> und die dokumentation im repository-root. direkte skriptaufrufe sind nur für
> komponentenentwicklung oder ausdrücklich dokumentierte recovery-diagnose
> vorgesehen.

dieses paket macht eine debian-12+/ubuntu-24.04+-wegwerf-VM in einem lauf
browserbereit: es installiert firefox, das offizielle mullvad-paket und
nftables, meldet die VM an, verbindet mullvad über shadowsocks auf port 443
und aktiviert anschließend auto-connect sowie lockdown.

## Interner legacy-installationspfad

der normale betreiberpfad legt eine neue VM mit
`flow enroll create --name NAME --profile vpn --host HOST --ssh-user USER` an.
der folgende downloadserver-einzeiler dient ausschließlich der isolierten
komponentenvalidierung oder dokumentierten recovery:

```sh
curl -fsSL https://downloads.example.com/install.sh|sh -s -- vpn
```

der befehl wird als normaler sudo-fähiger SSH-administrator (zum beispiel
`ubuntu`) und ohne vorangestelltes `sudo` gestartet. am besten wurde vorher
`ssh-gui-hardening` ausgeführt; dann wird firefox sofort für `malwarelab` als
standardbrowser eingerichtet. ein bereits geöffnetes firefox-fenster muss vor
dem lauf geschlossen werden. der bootstrap verwendet ausschließlich
passwortloses `sudo -n`; auf cloud-vms ohne benutzerpasswort erscheint deshalb
keine unlösbare sudo-passwortabfrage. der lauf muss aus einer direkten
IPv4-SSH-sitzung erfolgen, damit IPv6 ohne aussperrungsrisiko abgeschaltet
werden kann.

der normale quick-installer lässt mullvad den standort automatisch wählen.
das gebündelte PBP-setup ruft denselben verifizierten VPN-bootstrap mit
`--location de --skip-firefox --return-after-install` auf. in diesem modus
wird der browser erst weiter
eingerichtet, wenn mullvads HTTPS-check einen exit in deutschland bestätigt.
der distro-eigene firefox und seine globale policy werden dabei bewusst nicht
installiert, damit sie camoufox nicht mit widersprüchlichen einstellungen
beeinflussen.

der interne dynamicflow-one-shot-apply darf den installer ausdrücklich mit
`--outbound-https-enrollment` aus einer providerkonsole starten. dieser modus
verweigert eine vorhandene `SSH_CONNECTION`, verlangt ein kontrollierendes TTY
und überspringt ausschließlich die liveness-prüfung einer nicht vorhandenen
SSH-sitzung. mullvad-transport, deutscher egress, lockdown und auto-connect
werden weiterhin vollständig geprüft. schlägt die umschaltung fehl, bleibt die
VM absichtlich im lockdown (fail-closed); die wiederherstellung erfolgt dann
bewusst über die providerkonsole. der normale installer akzeptiert weiterhin
nur eine direkte IPv4-SSH-sitzung.

es erscheinen zwei verdeckte eingaben: zuerst das toolkit-download-passwort,
danach die mullvad-accountnummer. beide landen weder in der shell-history noch
in prozessargumenten oder logs.

## Netzwerkzustand danach

- sämtlicher normaler anwendungs- und firefox-verkehr läuft durch mullvad.
- die VM ist bewusst IPv4-only. IPv6 wird systemweit und im mullvad-tunnel
  deaktiviert, router advertisements werden abgeschaltet und bereits
  übernommene dynamische IPv6-routen entfernt, statt IPv6 möglicherweise
  ungeschützt ausweichen zu lassen.
- mullvads shadowsocks-transport ist fest auf port 443 gesetzt. das ist eine
  ausgehende VPN-verbindung und öffnet keinen eingehenden TCP-port 443.
- nur die effektiven SSH-serverports werden mit mullvads offiziellen
  nftables-marken vom tunnel ausgenommen. die dynamische öffentliche VM-IP
  muss deshalb nirgendwo gespeichert werden.
- VNC bleibt ausschließlich auf `127.0.0.1:5901`. sein externer transport ist
  der bereits ausgenommene SSH-tunnel; port 5901 erhält keine ausnahme.
- lockdown bleibt auch bei einer bewussten trennung aktiv und verhindert
  ungeschützten browserverkehr. auto-connect stellt den tunnel beim booten
  wieder her.

vor dem ersten connect läuft ein sechsminütiger systemd-rollback-timer. stirbt
der installationslauf oder schlägt eine prüfung fehl, schaltet er auto-connect
und lockdown aus und trennt mullvad. erst nach erfolgreichem shadowsocks-,
IPv4-, SSH- und benutzer-egresscheck wird der timer abgestellt.

die SSH-regel wird über drop-ins vor dem prozessstart von
`mullvad-early-boot-blocking.service` und `mullvad-daemon.service` geladen.
zusätzlich lädt `toolkit-mullvad-ssh-bypass.service` dieselbe geprüfte tabelle
nach dem early-boot-blocker nochmals und zwingend vor `ssh.service`; so kann der
blocker die management-ausnahme beim boot nicht in einem zwischenzustand
verlieren. nach dem lauf trotzdem einen frischen key-only-SSH-login, den
VNC-tunnel und anschließend einen neustart testen; eine bereits offene sitzung
allein beweist keinen erfolgreichen neu-login.

## Firefox

ubuntu 24.04 erhält den distro-eigenen firefox-snap, debian 12/13
`firefox-esr`. die systemweite firefox-policy setzt:

- kein browserproxy, damit das normale mullvad-systemrouting gilt,
- DNS-over-HTTPS gesperrt aus, damit mullvads DNS verwendet wird,
- WebRTC gesperrt aus, um eine zusätzliche browser-IP-oberfläche zu vermeiden,
- `${home}/Downloads` als downloadverzeichnis.

der vorhandene sichere xauthority-abgleich des toolkit-GUI-pakets wird auf
ubuntu sofort aktualisiert. der mullvad-management-socket und das lokale
`mullvad-exclude` bleiben für `malwarelab` unzugänglich.

docker-/decepticon-egress wird absichtlich nicht durch breite firewall-
ausnahmen „repariert“: container-routing und DNS müssen auf der jeweiligen VM
separat gegen eine mullvad-ausgangsadresse getestet werden.

vor dem löschen einer wegwerf-VM den geräteplatz freigeben:

```sh
sudo mullvad auto-connect set off
sudo mullvad lockdown-mode set off
sudo mullvad disconnect --wait
sudo mullvad account logout >/dev/null
sleep 10
```

das kompakte installationslog liegt root-only unter
`/var/log/toolkit-vpn-bootstrap.log`.
