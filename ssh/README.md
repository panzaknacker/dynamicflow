# SSH-/GUI-Bootstrap für eine isolierte Debian-/Ubuntu-VM

> **Legacy-/Komponentendokument:** Die hier beschriebenen Shell-Skripte sind
> interne Übergangs- und Komponentenwerkzeuge, nicht die normale
> dynamicflow-Benutzeroberfläche. Neue Bereitstellungen beginnen mit
> `flow --help` und `flow enroll create --profile ssh` beziehungsweise
> `--profile ssh-gui`. Direkte Skriptaufrufe sind nur für
> Komponentenentwicklung, den initialen Bootstrap oder ausdrücklich
> dokumentierte Recovery-Diagnose vorgesehen.

`vm-bootstrap.sh` richtet eine **bereits vorhandene** Debian-/Ubuntu-VM ein.
Es erstellt nicht die VM im Hypervisor. Für Windows Server wäre stattdessen ein
PowerShell-/RDP-Setup nötig. Ein historischer Komponentenlauf wurde auf Ubuntu
Server 24.04 (`x86_64`) durchgeführt; er ersetzt weder den aktuellen
signierten `flow`-Profilpfad noch den weiterhin offenen Vier-VM-E2E-Lauf.

Enthalten sind:

- ein beim Lauf explizit ausgewählter SSH-Public-Key;
- SSH nur mit Public Key, ohne Root-, Passwort-, Agent- oder X11-Login;
- optional XFCE plus TigerVNC auf `127.0.0.1:5901`;
- ein auf diesen VNC-Port beschränkter lokaler SSH-Tunnel;
- standardmäßig ein eigener, gesperrter GUI-Benutzer `malwarelab` ohne SSH-Login oder `sudo`;
- standardmäßig deaktivierte VNC-Zwischenablage.

Firefox wird weder installiert noch heruntergeladen. Das Skript verändert
außerdem keine Firewall und öffnet keinen VNC-Port nach außen.

`ssh-gui` richtet lediglich eine benutzerprivate X11-Authentifizierungsbrücke
für einen eventuell später bewusst installierten Firefox-Snap ein. Bei jedem
VNC-Start setzt die Sitzung `XAUTHORITY` auf `$HOME/.Xauthority` und spiegelt
den aktuellen TigerVNC-Cookie atomar mit Modus `0600` nach
`$HOME/snap/firefox/common/.Xauthority`. Deshalb können dieses Verzeichnis und
die Cookie-Kopie bereits existieren, obwohl Firefox nicht installiert ist. Der
Bootstrap startet, installiert oder lädt Firefox dabei nicht und verwendet kein
`xhost`.

## Interner Legacy-Komponentenablauf

Dieser direkte Ablauf dient nur der isolierten Komponentenvalidierung oder
einer ausdrücklich dokumentierten Recovery. Der normale Betreiberweg ist
`flow enroll create --name NAME --profile ssh` beziehungsweise
`--profile ssh-gui` mit signiertem Desired State.

Das Skript einmal herunterladen, prüfen und anschließend für beide Stufen exakt
dieselbe Datei verwenden:

```bash
curl -fsSLo ./vm-bootstrap.sh https://DEIN-SERVER/vm-bootstrap.sh
chmod 755 ./vm-bootstrap.sh
less ./vm-bootstrap.sh
sudo ./vm-bootstrap.sh key-only --user ubuntu --public-key-file ./admin.pub
```

Der zweistufige `key-only`-Ablauf setzt voraus, dass `openssh-server` bereits
installiert ist. Fehlt er, verweigert dieser Modus den Start eines ungeprüften
Distributions-sshd; dann nur mit funktionierender VM-Konsole den
Fail-closed-Einmalpfad `ssh` beziehungsweise `ssh-gui` samt
`--accept-lockout-risk` verwenden.

In einem zweiten Terminal mit dem zugehörigen **privaten** Schlüssel testen:

```bash
ssh -o IdentitiesOnly=yes \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -i ~/.ssh/DEIN_PRIVATE_KEY ubuntu@VM-IP true
```

Erst wenn das klappt, SSH härten und die GUI einrichten:

```bash
sudo ./vm-bootstrap.sh ssh-gui \
  --user ubuntu \
  --public-key-file ./admin.pub \
  --gui-user malwarelab \
  --confirm-key-tested
```

Wer bewusst alles per Einzeiler machen will und eine VM-/Cloud-Konsole zur
Wiederherstellung hat:

```bash
curl -fsSL https://DEIN-SERVER/vm-bootstrap.sh \
  | sudo bash -s -- ssh-gui \
      --user ubuntu \
      --public-key-file ./admin.pub \
      --gui-user malwarelab \
      --accept-lockout-risk
```

Dabei die VM-Konsole beziehungsweise die aktuelle SSH-Sitzung offen halten. Ein
Tippfehler beim Benutzer oder ein fehlender privater Schlüssel kann sonst zum
Aussperren führen.

Nur SSH ohne Desktop:

```bash
curl -fsSL https://DEIN-SERVER/vm-bootstrap.sh \
  | sudo bash -s -- ssh --user ubuntu --public-key-file ./admin.pub --accept-lockout-risk
```

`--user` kann entfallen, wenn `sudo` den richtigen `SUDO_USER` setzt. Explizit
ist bei einem Remote-Bootstrap sicherer.

## Historischer Toolkit-Serving-Pfad

Für das vorhandene Serving-Schema wird das Tool als `ssh` und als
target-unabhängiges Artefakt `any` paketiert:

```bash
./make-toolkit-release.sh v0.1.8
```

Der Builder erzeugt ausschließlich ein lokales, reproduzierbares Artefakt.
Veröffentlicht wird nie aus `ssh/`, sondern nur als Teil des vollständigen
Serving-Sets:

```bash
cd ../serving
./snapshot-current-tools.sh
./publish-release-set.sh
```

Das erwartete Remote-Artefakt ist `/tools/ssh/v0.1.8/any/ssh.tar.gz`. Der
öffentliche Toolkit-Installer prüft dessen äußere Versionsprüfsumme;
`bootstrap-ssh.sh` prüft danach zusätzlich alle Dateien innerhalb des Archivs.
Genau dieser eine Wrapper entspricht dem vorhandenen
`bootstrap*.sh`-Suchschema, übernimmt den aufrufenden Benutzer als
SSH-Administrator und wechselt kontrolliert mit `sudo` zu root.

Der Wrapper fragt bei jedem interaktiven Lauf nummeriert nach dem Public Key.
Er listet reguläre `~/.ssh/dynamic/*.pub`-Dateien auf und bietet immer die
nummerierte Standardoption „paste a public key“. Üblich ist, auf dem lokalen
Rechner `ssh-keygen -y -f ~/.ssh/dynamic/DEIN-KEY.pem` auszuführen und nur die
ausgegebene Public-Key-Zeile an der VM einzufügen.

Der sichere zweistufige Ablauf bleibt auch über das Toolkit erhalten, sofern
`openssh-server` bereits installiert ist. Zuerst nur den Key installieren:

```bash
TOOLKIT_AUTH='toolkit:PASSWORT' TOOLKIT_RUN_BOOTSTRAP=1 \
TOOLKIT_BOOTSTRAP_ARGS='key-only' \
sh -c 'curl -fsSL https://downloads.example.com/install.sh | sh -s -- ssh v0.1.8'
```

Danach den passenden privaten Key in einer zweiten Sitzung testen und exakt
dieselbe gepinnte Version härten:

```bash
TOOLKIT_AUTH='toolkit:PASSWORT' TOOLKIT_RUN_BOOTSTRAP=1 \
TOOLKIT_BOOTSTRAP_ARGS='ssh --confirm-key-tested' \
sh -c 'curl -fsSL https://downloads.example.com/install.sh | sh -s -- ssh v0.1.8'
```

Der bewusst riskantere Einmal-Aufruf nur für eine VM mit funktionierender
Cloud-Konsole:

```bash
TOOLKIT_AUTH='toolkit:PASSWORT' TOOLKIT_RUN_BOOTSTRAP=1 \
TOOLKIT_BOOTSTRAP_ARGS='--accept-lockout-risk' \
sh -c 'curl -fsSL https://downloads.example.com/install.sh | sh -s -- ssh v0.1.8'
```

Für SSH plus GUI lautet das Bootstrap-Argument `ssh-gui --accept-lockout-risk`.
Mit einer passenden `.netrc` kann `TOOLKIT_AUTH` wie im bestehenden
Toolkit-Runbook entfallen. Läuft der Installer bereits als root und hat deshalb
keinen `SUDO_USER`, muss in `TOOLKIT_BOOTSTRAP_ARGS` zusätzlich `--user ubuntu`
stehen.

Private SSH-Schlüssel, Host-Vertrauensdateien und andere lokale Zustandsdaten
sind weder im Raw-Release noch in `ssh.tar.gz` enthalten. Veröffentlicht wurde
während der Entwicklung nicht; geprüft wurde der Publisher mit `--dry-run`.

## GUI verbinden

Die Klartext-Kopie des generierten VNC-Passworts liegt ausschließlich für root
lesbar in der VM. TigerVNC legt zusätzlich eine lediglich obfuskierte
Passwortdatei für `malwarelab` an; deshalb bleibt VNC zwingend auf Loopback
beschränkt. Das Passwort wird nicht mehr mit einem allgemeinen
Root-Dateibefehl gelesen. Nur die bewusste, lokal auditierte `flow`-Operation
nutzt den festen Target-One-shot:

```bash
flow instance secret reveal NAME --secret vnc
flow instance secret rotate NAME --secret vnc
```

Der One-shot akzeptiert keine Pfade oder allgemeinen Befehle. Er prüft Root-
und Runtime-Dateien descriptor-relativ ohne Symlink-Following, exakte
Besitzer/Modi und Single-Link-Invarianten. Die Rotation ersetzt alle drei
Dateien im jeweiligen Verzeichnis atomar, synchronisiert Datei und Verzeichnis,
prüft die feste TigerVNC-Unit, `PasswordFile`, vncauth und Loopback und stellt
bei einem Fehler die zuvor verifizierten Bytes wieder her. Bei einem nicht
sicher wiederherstellbaren Zustand bleibt der Dienst gestoppt.

Der normale Operatorpfad startet den gehärteten Tunnel mit:

```bash
flow instance ssh NAME --gui --local-port 5901
```

Das folgende Hilfsskript bleibt nur für isolierte Komponentenvalidierung oder
Recovery-Diagnose:

```bash
./connect-gui.sh \
  --identity ~/.ssh/DEIN_PRIVATE_KEY \
  --known-hosts ~/.ssh/known_hosts \
  ubuntu@VM-IP
```

Beide Dateien sind Pflicht. Den SSH-Hostkey nur übernehmen, nachdem sein
Fingerprint über die VM-/Cloud-Konsole oder einen anderen unabhängigen Kanal
geprüft wurde; ein ungeprüftes `ssh-keyscan` allein schützt nicht vor einem
aktiven Erstverbindungsangriff. Der Helper lehnt Symlinks, fremde Besitzer,
unsichere Datei-/Verzeichnismodi, strukturell ungültige private Keys sowie
Pfade mit OpenSSH-Tokenexpansion ab; verschlüsselte private Keys bleiben
passphrasefähig.

Ohne Hilfsskript ist derselbe Tunnel:

```bash
ssh -NT \
  -F none \
  -S none \
  -o ConnectTimeout=12 \
  -o ConnectionAttempts=1 \
  -o ExitOnForwardFailure=yes \
  -o ForwardAgent=no \
  -o ForwardX11=no \
  -o IdentitiesOnly=yes \
  -o IdentityAgent=none \
  -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o StrictHostKeyChecking=yes \
  -o GlobalKnownHostsFile=none \
  -o UserKnownHostsFile=~/.ssh/known_hosts \
  -o UpdateHostKeys=no \
  -o ServerAliveInterval=15 \
  -o ServerAliveCountMax=3 \
  -o TCPKeepAlive=no \
  -L 127.0.0.1:5901:127.0.0.1:5901 \
  -i ~/.ssh/DEIN_PRIVATE_KEY \
  ubuntu@VM-IP
```

Danach einen VNC-Viewer mit `127.0.0.1::5901` verbinden. Manche Viewer erwarten
stattdessen `127.0.0.1:5901`.

Port `5901` darf in der Cloud-Firewall oder im Router **nicht** freigegeben
werden. Eine direkte Verbindung zu `VM-IP:5901` soll fehlschlagen.

## Firefox manuell übertragen

Firefox kann auf einem vertrauenswürdigen Rechner heruntergeladen und danach
per `scp` in die VM kopiert werden:

```bash
scp -i ~/.ssh/DEIN_PRIVATE_KEY firefox-*.tar.* ubuntu@VM-IP:/tmp/
```

Anschließend in der VM als Administrator nach `/home/malwarelab` kopieren und
den Besitz setzen oder Firefox bewusst über den Paketmanager installieren. Der
Bootstrap selbst lädt keinen Browser.

Wird stattdessen später bewusst der Firefox-Snap installiert, steht ihm die
beim VNC-Start aktualisierte Cookie-Kopie bereits zur Verfügung. Beide
`.Xauthority`-Dateien sind vertrauliche Zugangsdaten für das X11-Display; ihre
Rechte nicht ändern und sie nicht weitergeben.

## Optionen

```text
key-only                    Schlüssel installieren, sshd nicht härten
ssh                         Public-Key-only SSH, TCP-Forwarding aus
ssh-gui                     SSH plus XFCE/TigerVNC-Tunnel
--user USER                 vorhandener SSH-Benutzer
--public-key-file FILE      explizit ausgewählter Public Key (Direktaufruf)
--gui-user USER             GUI-Benutzer; Standard: malwarelab
--geometry WIDTHxHEIGHT     Standard: 1600x900
--gui-clipboard             Clipboard bewusst aktivieren
--replace-authorized-keys   bestehende authorized_keys sichern und ersetzen
--append-unrestricted-key   eingeschränkte Kopie desselben Keys bewusst umgehen
--confirm-key-tested        bestätigter Test des passenden privaten Schlüssels
--accept-lockout-risk       Einmal-Setup mit verfügbarer VM-Konsole erzwingen
```

Bestehende Schlüssel werden standardmäßig erhalten. „Public-Key-only“ bedeutet,
dass keine Passwortanmeldung möglich ist; es bedeutet nicht automatisch, dass
nur ein einziger Public Key akzeptiert wird. Der verwaltete Schlüssel ist der
beim Lauf ausgewählte Public Key; das Bundle enthält keinen festen Schlüssel.

Existiert derselbe Key bereits mit Einschränkungen wie `restrict`, `from=`,
`command=` oder `no-port-forwarding`, bricht der Bootstrap standardmäßig ab.
`--append-unrestricted-key` umgeht diese Einschränkungen bewusst und sollte nur
nach Prüfung der vorhandenen Zeile verwendet werden.

Die SSH-Authentifizierungsregeln gelten global. Andere Konten, die bislang nur
ein Passwort verwenden, verlieren dadurch den SSH-Zugang. Vorhandene
`Match`-Blöcke lehnt das Skript ab, weil deren Ausnahmen kein eindeutig globales
Ergebnis zulassen. Der GUI-Benutzer darf nicht derselbe Benutzer wie der
SSH-Administrator sein. Der Bootstrap erstellt und markiert ihn selbst als
dediziertes, gesperrtes Konto; ein bereits vorhandenes, nicht von ihm
markiertes Konto wird abgelehnt. Privilegierte Host-Gruppen und
sudoers-Freigaben sind ebenfalls unzulässig. Im Modus `ssh-gui` wird das Konto
zusätzlich über das effektiv geprüfte `DenyUsers` vom SSH-Login ausgeschlossen.

Fehlt `openssh-server` bei einem direkten `ssh`-/`ssh-gui`-Lauf, werden
`ssh.service` und `ssh.socket` während der Paketinstallation temporär
maskiert. Erst nach Schlüsselinstallation, Syntaxprüfung und effektiver
Konfigurationsprüfung wird SSH gestartet. Bei einem Fehler wird der
gestoppte/maskierte Endzustand nochmals geprüft und andernfalls kritisch vor
möglicher Exposition gewarnt. Bei vorhandenem SSH prüft der Bootstrap
Vendor-Unit, Drop-ins, exakte Startargumente und die tatsächliche
Listener-`cmdline`; nach HUP müssen zwei frische Loopback-Verbindungen
ausschließlich `publickey` angeboten bekommen. `key-only` ändert die
Authentifizierungsregeln dagegen absichtlich nicht und setzt deshalb einen
bereits installierten OpenSSH-Server voraus; fehlt er, bricht der Modus ab,
statt einen Server mit Distributionsstandard zu starten.

Ein späterer Lauf im Modus `ssh` deaktiviert den SSH-Tunnel wieder, lässt einen
bereits installierten TigerVNC-Dienst aber bestehen. Für die GUI deshalb
dauerhaft `ssh-gui` verwenden oder den VNC-Dienst manuell stoppen/deaktivieren.

## Betrieb und Kontrolle

```bash
sudo systemctl status 'tigervncserver@:1.service'
sudo ss -ltnp 'sport = :5901'
sudo sshd -T \
  -C user=ubuntu,host=127.0.0.1,addr=127.0.0.1,laddr=127.0.0.1,lport=22 \
  | grep -E '^(authenticationmethods|passwordauthentication|kbdinteractiveauthentication|permitrootlogin|allowtcpforwarding|permitopen|x11forwarding) '
```

Die erwartete VNC-Adresse ist ausschließlich `127.0.0.1:5901` beziehungsweise
`[::1]:5901`. Die GUI lässt sich bei Bedarf stoppen:

```bash
sudo systemctl stop 'tigervncserver@:1.service'
```

Vor dem Aktivieren des Dienstes lehnt der Bootstrap aktive fremde
TigerVNC-Defaults beziehungsweise Mandatory-Overrides ab. Er erkennt die
paketierte Perl- oder Legacy-Konfigurationssyntax und schreibt anschließend
eine root-eigene Mandatory-Policy für Loopback, `VncAuth`, Port 5901,
deaktiviertes X11-TCP, Sharing, eine feste, nicht vom VNC-Client änderbare
Desktop-Geometrie, `AllowOverride` und den gewählten Clipboard-Modus.
Unbekannte Formate werden nicht geraten, sondern abgelehnt. Zusätzlich
vergleicht er die tatsächlich verwendete `PasswordFile` bytegenau mit der
verwalteten Datei und prüft mit der bereits in der GUI-Grundphase installierten
`xdotool`-Runtime die effektive Geometrie, alle weiteren Laufzeitwerte sowie
jeden TCP-Listener auf Port 5901. Ein EXIT-/Signal-Fehler während der Prüfung
stoppt und deaktiviert die Unit; erst nach erfolgreicher Listener-, Policy- und
XFCE-Prüfung wird sie für den Boot aktiviert.

Diese Mandatory-Policy schützt den verwalteten TigerVNC-Dienst. Ein in der VM
bereits kompromittierter Benutzer kann grundsätzlich einen eigenen Server auf
einem anderen Port starten. Die Cloud-/Host-Firewall muss deshalb eingehend
ausschließlich die wirklich benötigten Dienste erlauben, typischerweise nur
SSH.

## Malware-Labor

- Eine wegwerfbare VM verwenden und vorher einen Snapshot erstellen.
- Dieser Bootstrap ist keine Netzwerksandbox. Den ausgehenden Internetzugang
  blockieren oder kontrollieren, bevor echte Malware gestartet wird.
- Kein Bridged Networking, keine Shared Folders, keine USB-Durchreichung und
  keine Host-Zwischenablage.
- Keine privaten Konten oder Zugangsdaten in der VM nutzen.
- VM, SSH-Hostkey und alle Daten darin nach dem Test als kompromittiert
  behandeln.
- Nach jedem Test auf den sauberen Snapshot zurückrollen oder die VM löschen.

VNC überträgt kein Audio. Für Malware, die Audio oder spezielle GPU-Funktionen
benötigt, ist eine andere Remote-Desktop-Lösung nötig.
