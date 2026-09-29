# Decepticon-Custom-VM-Datapack

> **Legacy-/Komponentendokument:** Dieses Datapack und seine direkten
> Build-/Kopier-/Bootstrap-Befehle sind interne Komponenten- und
> Validierungswerkzeuge, nicht der normale dynamicflow-Lifecycle.
> `decepticon` ist deklarativ als Profil eingeordnet, aber noch nicht im festen
> Target-Runner für einen produktiven Enrollment-Apply freigegeben. Direkte
> Skriptaufrufe nur für Komponentenentwicklung oder ausdrücklich dokumentierte
> Recovery-/Validierungsarbeit verwenden; normale Abläufe beginnen mit
> `flow --help`.

Dieses Verzeichnis enthält nur die Quellen des Datapacks. Der kanonische
Builder `../make-release.sh` ergänzt Version, Prüfsummen, den aktuellen
VPN-Bootstrap und das Decepticon-Bundle erst im fertigen Artefakt. Das Pack ist
für frische Linux-/Ubuntu-VMs gedacht und enthält dort:

- `decepticon-custom-vm.tar.gz`: die bereinigte Custom-Version
- `VERSION`: Release-/Image-Tag für diese Datapack-Version
- `BUILD_INFO`: Quell-Commit, Build-Ziel, Buildzeit und Bundle-Hash
- `SHA256SUMS`: Prüfsummen für Bundle, Skripte, Version und README
- `setup-mullvad.sh`: geprüfter Mullvad-Bootstrap für den vollständigen VM-Tunnel
- `bootstrap-decepticon-vm.sh`: installiert VM-Abhängigkeiten und Docker, entpackt die Custom-Version und baut lokale Images
- `troubleshoot-decepticon-vm.sh`: sammelt Diagnoseinformationen
- `fix-terminal.sh`: schneller Fix für `Error opening terminal: xterm-kitty`
- `fix-decepticon-postgres.sh`: Diagnose und optionaler Reset einer defekten frischen Postgres-Initialisierung

## Lokal auf die VM kopieren

```bash
DECEPTICON_ALLOW_DIRTY=1 ../make-release.sh
scp /path/to/dynamicflow/decepticon/dist/decepticon.tar.gz ubuntu@VM_IP:~/
```

Mit Key oder anderem Port:

```bash
scp -i ~/.ssh/id_ed25519 -P 2222 /path/to/dynamicflow/decepticon/dist/decepticon.tar.gz ubuntu@VM_IP:~/
```

## Auf der VM

```bash
mkdir decepticon-vm-datapack
tar -xzf decepticon.tar.gz --strip-components=1 -C decepticon-vm-datapack
cd decepticon-vm-datapack
sha256sum --strict -c SHA256SUMS
./bootstrap-decepticon-vm.sh --verify-only
./bootstrap-decepticon-vm.sh
```

Der letzte Befehl fragt die Mullvad-Accountnummer interaktiv und verdeckt über
das Terminal ab. Sie wird ausschließlich per stdin an die Mullvad-CLI
übergeben und erscheint weder in Prozessargumenten noch im Bootstrap-Log. Das
Setup verbindet Mullvad über Shadowsocks auf Port 443 und aktiviert danach
Auto-Connect sowie Lockdown.

Der Bootstrap wiederholt die vollständige Prüfsummenprüfung, bevor er Profile,
Pakete, Docker oder andere Systemzustände ändert. `--verify-only` prüft
zusätzlich Pfade und Archivtypen und beendet sich ohne Änderungen. Bei einem
Fehler nicht mit der Installation fortfahren, sondern Archiv und Downloadquelle
prüfen.

Nach dem Connect läuft der gesamte normale IPv4-Egress des Hosts über Mullvad.
Nach dem Docker-Build prüft der Bootstrap zusätzlich den Egress aus dem
gebauten Sandbox-Container. IPv6 wird auf Host- und Tunnelebene deaktiviert;
bei einem Tunnelabbruch blockiert Lockdown den normalen Egress fail-closed.
Einzige bewusste Routing-Ausnahme ist der effektive SSH-Port, damit die
Management-Verbindung zur VM außerhalb des Tunnels erreichbar bleibt. Beim
ersten Lauf deshalb aus einer IPv4-SSH-Sitzung arbeiten und die
Provider-/Cloud-Konsole geöffnet halten.

Der Decepticon-Bootstrap aktiviert Mullvads lokalen Netzwerkzugriff, weil die
LangGraph-, Datenbank- und Sandbox-Dienste über lokale Docker-Bridge-Netze
kommunizieren. Das erlaubt grundsätzlich auch Verkehr in andere lokale
Netze beziehungsweise die Cloud-VPC. Die veröffentlichten Decepticon-Ports
bleiben deshalb ausschließlich an `127.0.0.1` gebunden; auf der VM dürfen keine
zusätzlichen Dienste unbeabsichtigt an einer LAN-/VPC-Adresse lauschen.

Vor dem ersten Image-Build führt der Bootstrap vorhandene Docker-Daemon-
Einstellungen mit einer tunnelverträglichen MTU von 1280 zusammen, validiert
die resultierende Konfiguration und startet Docker nur bei einer tatsächlichen
Änderung neu. Beide Compose-Bridge-Netze tragen dieselbe MTU. Dadurch können
größere TLS-Pakete den kleineren Mullvad-WireGuard-Tunnel ohne PMTU-Blackhole
passieren.

Der öffentliche Toolkit-Installer zeigt während des langen System-, Docker-,
Build- und Egress-Abschnitts eine phasenbasierte Animation mit dem jeweils
wirklich erreichten Schritt. Es werden keine erfundenen Prozentwerte
angezeigt; die vollständige Ausgabe bleibt im geschützten Installationslog.

Wenn Docker gerade installiert wurde, ist die aktuelle SSH-Sitzung
möglicherweise noch nicht in der Gruppe `docker`. Dann:

```bash
newgrp docker
cd ~/decepticon-vm-datapack
./bootstrap-decepticon-vm.sh --skip-docker
```

Oder einmal ausloggen und neu per SSH anmelden.

Ein vorhandenes `~/Decepticon-custom` wird direkt weiterverwendet, wenn sein
Bundle-Marker exakt zur geprüften Version passt. Bei einem anderen gültigen
Toolkit-Bundle-Marker wird der bisherige Stand automatisch als
`.bak.TIMESTAMP` gesichert und das Upgrade fortgesetzt. Bei unbekanntem oder
unverwaltetem Inhalt bricht der Bootstrap sicher ab. Nur wenn auch ein solcher
Ordner bewusst gesichert und ersetzt werden soll:

```bash
./bootstrap-decepticon-vm.sh --force-extract
```

## Danach

```bash
decepticon --version
decepticon onboard --reset
decepticon start
```

Der Launcher liegt standardmäßig als root-eigenes Binary unter
`/usr/local/bin/decepticon`; das Runtime-Home ist automatisch
`~/.decepticon`. Deshalb funktionieren diese Befehle direkt ohne vollständigen
Pfad und ohne vorangestelltes `DECEPTICON_HOME=...`. Ein vorhandener alter
Launcher unter `~/.local/bin/decepticon` wird gesichert und durch einen Link
auf das neue System-Binary ersetzt, damit alte PATH-Reihenfolgen nicht die
vorige Version starten.

Den Bootstrap als normalen VM-Benutzer starten, nicht mit einem
vorangestellten `sudo`. Er fordert `sudo` nur für Pakete, Docker und das
System-Binary gezielt an. Das interaktive Mullvad-Setup verlangt absichtlich
einen normalen, sudo-fähigen Administrator in einer direkten IPv4-SSH-Sitzung;
ein direkter Root-Login wird dafür nicht unterstützt.

## Terminal-Problem `xterm-kitty`

Für die aktuelle SSH-Sitzung:

```bash
export TERM=xterm-256color
htop
```

Oder aus dem Pack:

```bash
source ./fix-terminal.sh
```

## Diagnose

```bash
./troubleshoot-decepticon-vm.sh
```

Postgres-Startproblem ansehen oder auf einer frischen VM zurücksetzen:

```bash
./fix-decepticon-postgres.sh
./fix-decepticon-postgres.sh --reset
```

Die Ausgabe landet zusätzlich in:

```bash
~/decepticon-vm-diagnostic.txt
```

Vor dem Löschen einer Wegwerf-VM Mullvad sauber abmelden, damit kein
Geräteplatz belegt bleibt:

```bash
sudo mullvad auto-connect set off
sudo mullvad lockdown-mode set off
sudo mullvad disconnect --wait
sudo mullvad account logout >/dev/null
sleep 10
```

## Wichtig

Dieses Pack lädt keine Decepticon-Installer, keine Decepticon-Konfiguration und
keine Decepticon-Images vom ursprünglichen Maintainer. Das eingebettete
`setup-mullvad.sh` installiert das offizielle Mullvad-Paket; Docker lädt beim
Build normale Basisimages und Paketquellen von Drittanbietern wie
Ubuntu/Debian, Docker, Python/Node, LiteLLM, Postgres und Neo4j. Versionierte
Datapacks enthalten getrennte Linux-Launcher für amd64 und arm64; der Bootstrap
wählt nur ein zur VM-Architektur und zum Datapack-Tag passendes Binary.
