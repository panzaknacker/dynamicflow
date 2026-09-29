# `pbp-m`: normaler PBP-Setup- und Verbindungsweg

Der normale Einstieg ist lokal aus dem PBP-Projektverzeichnis:

```sh
./pbp-m
```

Ohne Argumente zeigt der Wrapper dieses Menü; Auswahl `1` ist die Vorgabe:

```text
PBP:
  1) Neue disposable PBP-VM komplett einrichten
  2) Vorhandene PBP-VM verbinden
Auswahl [1]:
```

`pbp-m` erstellt keine VM über eine Cloud-API. Die leere Wegwerf-VM wird
zuerst bei einem beliebigen Provider angelegt; danach übernimmt Menüpunkt `1`
die vollständige Konfiguration. Weder flow/serving noch ein aus dem Netz
ausgeführter Shell-Einzeiler gehören zu diesem Normalweg.

## Aktueller Test-ONLY-Status

Der aktuelle Camoufox-/Gecko-Pin besteht das normale Security-Release-Gate
nicht. `pbp-m` führt vor dem Setup zuerst das unveränderte Release-Gate und
danach das eng begrenzte Disposable-Testgate aus. Nur wenn dieses genau den
zulässigen Test-ONLY-Zustand bestätigt, bietet der Wrapper den markierten
Testbuild an. Zusätzliche oder unbekannte Fehler brechen den Lauf ab.

Die Warnung muss am kontrollierenden Terminal bestätigt werden. Der
Testbrowser darf ausschließlich auf dieser Wegwerf-VM und ohne sensible
Website-Accounts, Passwörter oder Daten benutzt werden. Die Zustimmung ändert
weder Browser-Pins noch Review-Policy oder das normale Release-Gate.
`--accept-disposable-test-browser` überspringt nur diese zweite Ja/Nein-Frage;
Cloud-Firewall und Hostkey müssen weiterhin interaktiv verifiziert werden.

## Voraussetzungen

Vor `./pbp-m` eine neue Wegwerf-VM mit folgenden Eigenschaften anlegen:

- Debian 12+ oder Ubuntu 24.04+, systemd, `amd64` oder `arm64`; falls das
  Image cloud-init verwendet, muss dessen Initialisierung abgeschlossen sein;
- literale öffentliche IPv4-Adresse;
- normaler SSH-Administrator ohne root, standardmäßig `ubuntu`;
- der öffentliche Teil des später in `pbp-m` gewählten SSH-Keys ist bereits
  als initialer Zugang hinterlegt;
- passwortloses `sudo` für diesen Administrator;
- echte, vom VM-Ingress unabhängige serielle/KVM-/VNC-Konsole. Ein
  Browser-SSH-Gateway ist nur dann Recovery, wenn es den zu konfigurierenden
  Firewallpfad nachweislich umgeht;
- ausgehende Cloud-Regeln zunächst unverändert beziehungsweise `allow all`;
- gültige Mullvad-Accountnummer und freier Geräteplatz.

Lokal werden die aktuelle PBP-Arbeitskopie, das benachbarte SSH-/GUI-Projekt,
die gepinnten Vendor-Artefakte sowie OpenSSH-Werkzeuge benötigt. Die
Access-Adresse wird nicht durch einen externen Dienst ermittelt: Bei
`IP für Access:` ist die tatsächlich für diese SSH-Verbindung verwendete
öffentliche IPv4-Adresse des Clients einzugeben. Ein lokaler VPN-, NAT- oder
Uplinkwechsel kann diese Adresse ändern.

## Neue VM vollständig einrichten

Menüpunkt `1` entspricht:

```sh
./pbp-m --setup
```

### 1. Lokale Eingaben und Prüfungen

Der Wrapper arbeitet diese Eingaben ab, bevor er die Cloud-Freigabe
bestätigen lässt:

1. `Neue VM (öffentliche IP oder USER@IP):` akzeptiert ausschließlich eine
   literale, global routbare IPv4-Adresse; DNS und IPv6 sind ausgeschlossen.
2. Unter `~/.ssh` wird interaktiv ein regulärer, benutzereigener und nicht für
   Gruppe oder Welt lesbarer privater Key gewählt. Struktur und zugehöriger
   Public Key werden mit OpenSSH geprüft.
3. `IP für Access:` akzeptiert eine einzelne globale IPv4-Adresse und
   normalisiert sie auf exakt `/32`; größere Netze werden abgelehnt.
4. Eine Persona wird für die gesamte Wegwerf-VM festgelegt:

   - `basic`: 4 CPU-Threads, Intel HD 400, `1600x900`;
   - `performance`: 8 CPU-Threads, NVIDIA GTX 980, `1600x900`;
   - `workstation`: 12 CPU-Threads, Intel HD, `1600x900`.

   Die Wahl bleibt mit dem Browserprofil VM-stabil. Ein späterer
   Klassenwechsel erfordert eine frische Wegwerf-VM.
5. Sofern anschließend ein GUI-Tunnel geöffnet werden soll, muss der lokale
   Port `127.0.0.1:5901` beziehungsweise `--local-port` frei sein. Mit
   `--no-open` startet kein Tunnel; deshalb überspringt `pbp-m` sowohl die
   Connector- als auch die lokale Portprüfung. Danach läuft das oben
   beschriebene Browser-Sicherheitsgate.

`--yes` und ein Allowlist-Adapter sind beim neuen Setup absichtlich verboten;
externe Cloud-Zustände dürfen hier nicht blind bestätigt werden.

### 2. Finaler providerneutraler Cloud-Firewall-Zustand

`pbp-m` zeigt VM, SSH-Login, lokalen Key, Access-IP, Persona und Buildstatus an.
Danach ist in der Provider-Control-Plane exakt dieser Zustand herzustellen:

```text
INBOUND
  ALLOW TCP <SSH-PORT> FROM <ACCESS-IP>/32 TO <GENAU-DIESE-VM>
  sonst keine Inbound-Regel für diese VM

OUTBOUND
  unverändert / allow all
```

Dabei gelten folgende Invarianten:

- Jede am Ziel wirksame Cloud-Firewall, Security Group, Projekt- oder
  Netzwerk-Firewall und ACL muss einbezogen werden. Eine breite Regel in nur
  einer weiteren additiv wirkenden Ebene macht die `/32`-Allowlist unwirksam.
- Falls noch keine Cloud-Firewall aktiv oder angehängt ist, zuerst das
  vollständige Objekt erstellen, der exakten VM zuordnen und die aktive
  Übernahme abwarten.
- Vor der Bestätigung sämtliche breiteren SSH-Regeln entfernen: kein
  `0.0.0.0/0`, kein größeres IPv4-Netz und keine IPv6-Inbound-Regel.
- TCP `5901` niemals öffentlich freigeben. VNC bleibt ausschließlich hinter
  dem SSH-Tunnel auf VM-Loopback.
- Outbound bei diesem Schritt nicht verschärfen. Installation, DNS, HTTPS,
  Mullvad-Shadowsocks Port 443 und der VPN-Tunnel müssen funktionieren.
- Die echte unabhängige Provider-/Recovery-Konsole offen lassen, bis die
  frischen SSH-Prüfungen nach der Härtung bestanden sind.

`pbp-m` ändert selbst keine Cloud-API. Erst wenn der finale Zustand aktiv und
der richtigen VM zugeordnet ist, die einfache Frage am kontrollierenden
`/dev/tty` mit `y` bestätigen:

```text
Cloud-Firewall ist exakt so aktiv und der VM zugeordnet? [y/N]: y
```

Pipe-/stdin-Bestätigungen werden nicht akzeptiert. Eine Bestätigung beweist
die Cloud-Konfiguration nicht technisch; die anschließenden frischen
SSH-Anmeldungen prüfen den tatsächlich erreichbaren Pfad.

### 3. SSH-Hostkey pinnen; unabhängiger Vergleich optional

Nach dem Cloud-Gate liest `pbp-m` genau einen Ed25519-Hostkey-Kandidaten von
der VM. Standardmäßig (`[Y/n]`) wird angeboten, dessen Fingerprint über die
vom Netzwerkpfad unabhängige Providerkonsole zu prüfen:

```sh
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Nur den dort ausgegebenen `SHA256:...`-Fingerprint in
`Fingerprint aus Providerkonsole:` übernehmen. `ssh-keyscan` allein ist kein
Vertrauensanker. Bei Übereinstimmung speichert der Wrapper einen exakten,
privaten Pin mit Modus `0600` unter:

```text
~/.ssh/pbp-m-known-hosts/<VM-IP-MIT-UNTERSTRICHEN>-<SSH-PORT>.known_hosts
```

Für `203.0.113.20` und Port `22` wäre der Dateiname beispielsweise
`203_0_113_20-22.known_hosts`.

Die Konsolenprüfung ist optional. Wer die Frage mit `n` beantwortet, lässt
den von `ssh-keyscan` beobachteten Schlüssel als TOFU-Pin speichern. `pbp-m`
zeigt dabei eine deutliche Warnung. Dieser einfachere Weg schützt spätere
Verbindungen durch Pinning, kann aber einen Angreifer beim allerersten Kontakt
nicht ausschließen.

Beim nächsten Lauf wird dieser Pin automatisch wiederverwendet. Ein bereits
unabhängig verifizierter Pin kann stattdessen mit `--known-hosts` übergeben
werden; `--hostkey-fingerprint SHA256:...` erlaubt die vorherige Eingabe des
separat ermittelten Fingerprints. Diese beiden Optionen sind alternative
Vertrauensanker und dürfen beim Setup nicht kombiniert werden.

### 4. Lokaler Build, Upload und Remote-Härtung

Nach erfolgreichem Pinning läuft der restliche Setup in einem gehaltenen,
streng gepinnten SSH-Provisioning-Kanal:

1. Remote-Preflight auf normalen Benutzer, passwortloses `sudo`, systemd,
   Debian-/Ubuntu-Version und Architektur; ein vorhandenes cloud-init wird mit
   festem Zeitlimit abgewartet.
2. Lokaler Build des aktuellen SSH-/GUI-Artefakts und des zur VM-Architektur
   passenden PBP-Artefakts. Beim blockierten Browserstand entsteht nur das
   klar markierte Disposable-Testartefakt.
3. Upload der beiden validierten Archive und des aus dem privaten Key
   abgeleiteten Public Keys in ein zufälliges, privates Remote-Staging. Der
   private SSH-Key verlässt den lokalen Rechner nie.
4. SHA-256-Prüfung und sichere Entpackprüfung auf der VM.
5. Installation und Härtung von SSH, XFCE und TigerVNC. Der ausgewählte
   Public Key ersetzt dabei die administrativen `authorized_keys`; andere
   dort vorhandene Keys werden entfernt. Direkt danach muss eine neue, vom
   gehaltenen ControlMaster unabhängige SSH-Anmeldung erfolgreich sein.
6. Installation von Mullvad und PBP. Wenn noch kein Mullvad-Account angemeldet
   ist, wird seine Nummer verdeckt über das Terminal abgefragt. Mullvad wird
   auf Deutschland, Shadowsocks Port 443, Auto-Connect und Lockdown gesetzt;
   IPv6 wird systemweit deaktiviert.
7. Zweite frische SSH-Anmeldung nach Mullvad/PBP sowie Abschlussprüfung von
   Persona, VPN-Policy, PBP-Launcher, TigerVNC-Dienst und ausschließlich an
   `127.0.0.1:5901` beziehungsweise `[::1]:5901` gebundenem VNC-Listener.
8. Entfernung des Remote-Stagings und Ende des Provisioning-ControlMasters.

Der gehaltene Kanal ist kein Ersatz für die unabhängige Providerkonsole. Bei
einem Teilfehler meldet `pbp-m` die VM nicht als bereit; ein möglicherweise
verbliebener Staging-Pfad wird angezeigt, und der Zustand kann nur teilweise
konfiguriert sein. Diese VM nicht weiterverwenden. Bei einer Wegwerf-VM ist
der Neuaufbau sicherer als eine improvisierte Teilreparatur.

### 5. VNC-Passwort und Tunnel

Nach vollständiger Prüfung zeigt `pbp-m` am kontrollierenden Terminal:

- VM und Persona;
- `security release` oder `DISPOSABLE TEST-ONLY`;
- das erzeugte achtstellige VNC-Passwort;
- `127.0.0.1:5901 -> VM 127.0.0.1:5901`.

Das VNC-Passwort ist vertraulich. Ohne `--no-open` startet anschließend der
gehärtete SSH-Tunnel und bleibt im Vordergrund. Einen lokalen VNC-Viewer mit
`127.0.0.1::5901` verbinden; manche Viewer erwarten `127.0.0.1:5901`. Im
Desktop als `malwarelab` den Eintrag **PBP browser** öffnen. Niemals den Viewer
mit `VM-IP:5901` verbinden.

Mit `--no-open` endet das Setup nach der Abschlussausgabe. Weil dabei kein
Tunnel gestartet wird, werden Connector und lokaler Tunnelport bewusst nicht
geprüft. Später genügt Menüpunkt `2` beziehungsweise `./pbp-m --connect`; der
verwaltete Hostkey-Pin wird automatisch gefunden.

Nach Ende des Laufs erinnert `pbp-m` daran, die manuell gesetzte `/32`-Regel
aus allen wirksamen Cloud-Ebenen zu entfernen. Der Wrapper kann eine manuelle
Regel weder verifizieren noch löschen.

## Sekundär: vorhandene VM verbinden

Für eine bereits eingerichtete PBP-VM Menüpunkt `2` wählen oder explizit:

```sh
./pbp-m --connect
```

Dieser Modus provisioniert nichts neu. Vor dem Cloud-Gate werden Ziel-IP,
exakter Hostkey-Pin, privater Key, Connector, SSH-Port und freier lokaler
Tunnelport geprüft. Danach fragt `pbp-m` direkt `IP für Access:`, verlangt
erneut den finalen `/32`-Firewallzustand, verlangt eine direkte
`[y/N]`-Bestätigung und öffnet erst dann den Tunnel. `--yes` ist im manuellen
Modus ein harter Fehler.

Der vom Setup verwaltete Pin wird automatisch bevorzugt; nur für einen
anderen bereits verifizierten Pin ist `--known-hosts DATEI` nötig. Bekannte
Werte können explizit übergeben werden:

```sh
./pbp-m --connect \
  --source-ip DEINE_AKTUELLE_OEFFENTLICHE_IPV4 \
  --identity ~/.ssh/dynamic/pbp_ed25519 \
  ubuntu@OEFFENTLICHE_VM_IPV4
```

Auch hier VNC ausschließlich lokal über `127.0.0.1:5901` verwenden und die
manuelle Cloud-Regel nach Tunnelende entfernen.

## Optionaler Adaptermodus nur für bestehende VMs

Ein providerseitiger Adapter ist ausschließlich eine sekundäre Option des
Connect-Modus. Das Setup einer neuen VM lehnt ihn ab. Beispiel:

```sh
./pbp-m --connect \
  --whitelist-helper ~/.local/libexec/pbp-m-whitelist \
  --source-ip DEINE_AKTUELLE_OEFFENTLICHE_IPV4 \
  ubuntu@OEFFENTLICHE_VM_IPV4
```

Alternativ aktiviert `PBP_M_WHITELIST_HELPER` denselben Modus. Nur hier darf
`--yes` die einfache Lease-Zusammenfassung überspringen. Der Helper wird ohne
Shell aufgerufen.

Anfordern:

```text
ADAPTER acquire \
  --host IPv4 \
  --source-cidr IPv4/32 \
  --ssh-port PORT \
  --ttl-seconds TTL
```

Nach bestätigter Aktivierung muss Exitcode `0` und exakt dieses begrenzte JSON
auf stdout folgen:

```json
{
  "schema": "dynamicflow/pbp-m-whitelist/v1",
  "lease_id": "provider-opaque-lease-id",
  "host": "203.0.113.20",
  "source_cidr": "198.51.100.24/32",
  "ssh_port": 22
}
```

Freigeben:

```text
ADAPTER release --lease-id provider-opaque-lease-id
```

Der Adapter muss das eindeutig zum literalen Ziel gehörende Objekt atomar
ändern, die TTL providerseitig erzwingen und `release` idempotent
implementieren. Er darf niemals fremde Regeln löschen. `pbp-m` validiert die
Antwort exakt und gibt die Lease bei normalem Ende, Fehler und behandelten
Signalen frei. Die providerseitige TTL bleibt Pflicht, weil kein lokaler
Cleanup `SIGKILL` oder einen Hostausfall abfangen kann.

Die Adressen im JSON stammen aus Dokumentationsnetzen und werden vom Programm
absichtlich nicht als global routbare Ziel- oder Access-Adressen akzeptiert.
