# ADR 0001: Dynamicflow-Control-Plane und Vertrauensgrenzen

- Status: angenommen
- Datum: 22.07.2026
- Letzter Abgleich mit der Implementierung: 23.07.2026

## Kontext

Dynamicflow bestand aus voneinander unabhängigen Shell-Einstiegspunkten für
Build, Veröffentlichung, SSH, GUI, VPN, PBP, Decepticon und Examstation.
Artefakt und Prüfsumme konnten vom gleichen Downloadserver stammen; es gab
kein einmaliges VM-Enrollment, keinen signierten Desired State und keine
einheitliche Verwaltung der Betreiber-SSH-Identitäten. Ein kompromittierter
Downloadserver konnte damit zugleich Nutzdaten und deren behauptete Prüfsumme
ersetzen. Das historische SSH-Release `v0.1.5` enthält außerdem einen festen,
nicht autorisierten Public Key und darf nie wieder installierbar werden.

Die Benutzerbegriffe sind verbindlich:

- Gesamtprojekt: **dynamicflow**
- CLI: **flow**
- interner HTTPS-Verteil- und Enrollment-Knoten: **serving**
- verwaltete Ziel-VM: **instance**
- installierbare deklarative Konfiguration: **profile**

## Entscheidung

### 1. Eine Go-CLI, schmale interne Laufzeiten

`flow` ist ein statisch baubares Go-Programm. Derselbe Quellbaum stellt drei
klar getrennte Oberflächen bereit:

1. die dokumentierte Betreiber-CLI;
2. den internen, unprivilegierten HTTPS-Prozess `flow serve` unter systemd;
3. den Linux-root-only One-shot `flow instance-runtime` auf einer Ziel-VM,
   ausgelöst durch einen festen persistenten systemd-Timer.

Die beiden internen Einstiegspunkte erscheinen nicht in der normalen
`flow --help`-Oberfläche. Python bleibt die PBP-/Camoufox-Laufzeit. Bestehende
Shell-Installer dürfen nur als versionierte, fest ausgewählte Component-
Executoren weiterlaufen. Remote-Daten können weder einen Skriptnamen noch freie
Argumente oder allgemeine Root-Kommandos festlegen.

### 2. Getrennte Schlüsselrollen

| Schlüssel | Private Hälfte | Public Hälfte | Zweck |
| --- | --- | --- | --- |
| Release-Signing | nur Operator | Serving, Instances | Manifest und Artefaktbindungen autorisieren |
| Desired-State-Signing | nur Operator | Serving, Instances | Instanz, Profil, Generation und SSH-Public-Keys autorisieren |
| Control | nur Operator | Serving | kurzlebig signierte Admin-HTTPS-Requests |
| SSH je Instanz (Standard) | nur Operator | über Desired State zu Serving/Instance | expliziter Direktzugriff |
| Instance Identity | nur betreffende Instance | Serving | signierte Status-, Log- und Desired-State-Requests |
| TLS-Transport | Serving | Operator und Instances pinnen das Zertifikat | HTTPS-Kanal, keine Content-Autorisierung |

Release-, Desired-State- und Control-Key sind voneinander verschieden. Ein
Deploy- oder TLS-Key ist kein Signing-Key. Kein privater SSH-Key gelangt ins
Repository, zu Serving oder auf eine Ziel-VM.

### 3. Signierte, unveränderliche Release-Sets

Das kanonische Release-Manifest bindet Ed25519-signiert mindestens
Komponente, Version, Target, relativen Artefaktpfad, SHA-256 und Größe. Die
`set_id` deckt alle sicherheitsrelevanten Manifestfelder ab. Veröffentlichung:

1. Signatur und jedes Artefakt prüfen;
2. in ein neues Set-Verzeichnis kopieren und erneut prüfen;
3. Dateien schreibgeschützt setzen und Verzeichnisse synchronisieren;
4. `current` atomar auf das vollständige Set umschalten.

Bundle und Manifest haben feste Größen- und Mengenobergrenzen. Alle
Release-Quellen und Importziele werden descriptor-relativ mit `O_NOFOLLOW`,
`O_NONBLOCK` sowie Owner-, Single-Link- und Modusprüfung geöffnet;
Private-Key-Marker werden auch in gzip-komprimierten Tar-Inhalten abgelehnt.
Übergeordnete Verzeichnisse der Release-Wurzel müssen root- oder dienst-eigen
sein; beschreibbare Eltern sind ausschließlich mit Sticky-Semantik zulässig.
Publish hält den geprüften Root-FD über die gesamte Transaktion und vergleicht
`dev/inode`, Owner und Mode vor jeder Set-, History- und `current`-Commit-Grenze.
Ein Rename-Swap kann dadurch weder das Ziel noch den zugehörigen Lock
austauschen. Eine `{Komponente, Version, Target}`-Koordinate darf über alle
Generationen nur genau einen Artefaktnamen, Digest und eine Größe bezeichnen.
Der Build prüft dies **vor** der Signatur gegen den privaten,
signaturverifizierten Operator-Manifestkatalog, das letzte Stage und vorhandene
Legacy-Artefakte. Serving prüft es erneut gegen alle Sets und kleine, dauerhaft
aufbewahrte signierte Manifest-Tombstones unter `history/`.

Der private Operator-Katalog besitzt zusätzlich den nur für den Owner lesbaren
Checkpoint `manifest-history.index.json` mit vollständiger Set-Liste und
Generations-High-Water. Fehlende checkpointete Einträge, ein gelöschtes
History-Verzeichnis oder ein bestehendes Stage ohne Checkpoint blockieren
Build, Verify und Publish. Ein nichtleerer, aber nicht checkpointeter Katalog
wird niemals automatisch als vollständig angenommen; eine Migration eines
Altzustands ist eine explizite auditierte Recovery-Operation. Explizite
Generationen müssen oberhalb der gesamten privaten Historie liegen; nur der
bytegleiche Rebuild derselben Set-ID darf dieselbe Generation verwenden. Bei
automatisch gewählter Generation setzt ein Uhr-Rücklauf den Wert auf
`High-Water + 1`, statt einen Rollback zu signieren.

Die monotone High-Water-Marke ist die höchste Generation aus aufbewahrten Sets
und Manifest-Tombstones. Ein manipulierter oder zurückgesetzter
`current`-Pointer und normales Artefakt-Pruning können deshalb keinen
niedrigeren Kandidaten oder ein Version-Rebinding autorisieren. Der
Publish-Plan führt dieselbe Prüfung lokal beziehungsweise über einen
control-signierten, schreibgeschützten HTTPS-Preflight aus; der echte Publish
wiederholt sie unter dem Publish-Lock. Release-Signing und
Control-Autorisierung bleiben getrennte Ed25519-Wurzeln.

Auf dem Operator teilen Build, Verify, Publish und Publish-Plan einen nicht
blockierenden Release-Lock über Stage und Artefaktpfade. Eine zweite Operation
wartet nicht und arbeitet insbesondere nicht mit einem gemischten Buildstand,
sondern endet mit `release_busy`. Der Lock bleibt beim Remote-Publish bis nach
dem Streaming und dem verifizierten Aktivierungsbeweis gehalten.

Beim Build wird zuerst das content-addressed History-Manifest, danach der
kanonische Manifestexport und zuletzt `staged.json` geschrieben. Dieses Stage
ist der Commit-Marker; Verify und Publish verlangen exakte Übereinstimmung mit
dem Export. Ein Abbruch zwischen den atomaren Writes blockiert daher bis zu
einem erfolgreichen Rebuild. Beim Publish gilt Set → History → `current`.
Liegt das vollständig signatur-, digest-, owner- und modeverifizierte Set nach
einem Abbruch bereits vor, kann der lokale Operator History und `current` auch
ohne die flüchtigen Upload-Dateien fertigstellen.

`current` ist nur die Vorgabe für neue Desired States und neue Rollouts. Ein
bereits signierter Desired State bindet seine Instanz an genau seine
unveränderliche Set-ID; Manifest und Artefakte werden deshalb über einen
Set-ID-spezifischen HTTPS-Pfad bezogen. Das Umschalten von `current` darf einen
laufenden oder noch nicht abgeholten älteren Desired State weder still
umbinden noch uninstallierbar machen. Referenzierte Sets dürfen erst durch
einen gesonderten, auditierten Pruning-Ablauf nach Ablauf oder Ersetzung aller
Desired States entfernt werden. Ihre signierten `history/`-Tombstones werden
dabei niemals entfernt; ein Wechsel des Release-Signing-Keys ist deshalb eine
explizite Trust-Domain-Migration mit alten und neuen Verifikationswurzeln, kein
stiller Dateiaustausch.

Downgrade, gleiche Generation mit anderem Inhalt, Symlink-Traversal und
widerrufene aktive Versionen werden abgelehnt. `ssh:v0.1.5` ist im Builder
zwingend widerrufen. Serving aktiviert nur einen bereits verifizierten Satz und
besitzt keinen Signing-Key.

### 4. Serving ist Verteiler, kein Root-Command-Server

```text
                         signierte HTTPS-Steuerung
  Operator + Signing Keys ------------------------------> serving
       |                                                       ^
       | explizites, gepinntes SSH                             | nur ausgehendes HTTPS
       v                                                       |
    instance --------------------------------------------------+
```

Serving stellt nur Health, Bootstrap, das aktuelle sowie per Set-ID
adressierte signierte Manifest, manifestgebundene Artefakte, Enrollment,
Desired State, finite Statusberichte und bereinigte Ereignislogs bereit.
Control- und Instance-Requests binden Methode, Pfad, Body, Zeitpunkt und Nonce.
Es existiert kein `/exec`- oder allgemeiner Job-Endpunkt. Serving initiiert nie
SSH zu einer Ziel-VM.

Der Serving-Prozess läuft als dedizierter Benutzer mit leerem Capability-Set,
schreibgeschütztem System und ausschließlich seinem privaten State als
Schreibbereich. TLS wird direkt terminiert; Forwarded-Header sind keine
Vertrauensquelle.

### 5. Einmaliges, gebundenes Enrollment

Der Operator erzeugt standardmäßig einen lokalen Ed25519-SSH-Key pro Instanz
und signiert einen Desired State. Serving erzeugt danach ein zufälliges
Enrollment-ID-/Secret-Paar, speichert nur den Secret-Digest und bindet es an
Instanz, Profil, Ablaufzeit und Desired State. Konsum und Replay-Status werden
unter exklusivem Lock atomar geschrieben.

Die Instanz erzeugt zusätzlich ihre eigene Ed25519-Identität. ID und Secret
werden im HTTPS-POST-Body übertragen; auf der VM liest `flow` sie verdeckt aus
`/dev/tty` oder aus exakt begrenztem stdin. Sie sind weder URL, Argument noch
Umgebungsvariable. Nach erfolgreichem Konsum wird der Code ungültig. Geht die
HTTP-Antwort verloren, verwendet ein erneuter Lauf dieselbe stabile
Instance-Identität und versucht, den signierten Desired State
wiederzugewinnen.

### 6. Deklarativer Apply mit Journal und Fail-closed

Die Instanz prüft unabhängig:

- Release- und Desired-State-Signaturen mit getrennten gepinnten Public Keys;
- Instanz-, Profil-, Release-Set-, Generations- und Target-Bindung;
- exakte Übereinstimmung des signierten Profilgraphen mit dem eingebauten
  lokalen Graphen;
- jedes gestreamte Artefakt anhand Größe und Digest vor und nach dem Cache.

Ein exklusiver Apply-Lock und ein kanonisches Journal mit Modus `0600` halten
Preflight, Apply, Verify, Fehlzustand und Resume fest. Der Journal-Digest bindet
den vollständigen verifizierten Plan einschließlich Public Keys und
Artefaktdigests. Ein Checkpoint wird erst nach vollständiger Verifikation aller
Phasen vorgerückt. SSH-Fehler stoppen die SSH-Dienste; VPN-/PBP-Fehler lassen
den Mullvad-Lockdown aktiv und trennen den Tunnel. Es gibt keinen unsignierten
Fallback.

Jeder Apply-Plan beginnt zwingend mit genau einem architekturgebundenen,
rohen `flow`-Artefakt. Die Instanz lädt und prüft es content-addressed, sichert
vor dem ersten Austausch auch das bisher laufende, geschützte Binary unter
`apply/runtime-recovery/<sha256>.flow` und ersetzt ausschließlich
`/usr/local/bin/flow` descriptor-relativ per atomarem Rename. Recovery-Dateien
sind root-eigen, Modus `0700`, Single-Link und nach Größe und Digest geprüft.
Nach einem echten Austausch beendet die alte Invocation den Lauf als
expliziten Handoff: Sie führt keine SSH-, VPN- oder PBP-Phase aus und schreibt
keinen Apply-Checkpoint. Erst der nächste systemd-Timerlauf startet den festen
Pfad mit dem neuen Binary und setzt denselben gebundenen Plan fort. Ein
automatischer Downgrade ist absichtlich ausgeschlossen; ein nicht startbares
signiertes Binary erfordert die dokumentierte Providerkonsolen-Recovery.

Der signierte vollständige SSH-Key-Satz wird vor dem festen SSH-Installer
atomar aktiviert und in der Verify-Phase danach erneut descriptor-relativ
bestätigt. Installer-Drift, Symlinks, Hardlinks oder falsche Metadaten können
damit keinen erfolgreichen Checkpoint erzeugen.

Beim Enrollment schreibt die Runtime vor dem Lesen des Secrets beide
Unit-Dateien per atomarem Replace und aktiviert
`dynamicflow-instance-reconcile.timer`; der zugehörige Service heißt
`dynamicflow-instance-reconcile.service`. Der Timer startet ausschließlich
`flow instance-runtime reconcile --state-root
/var/lib/dynamicflow/instance`, läuft persistent im Fünf-Minuten-Takt mit
begrenztem Jitter und nimmt keine Operator- oder Remote-Kommandos an. Ein
`ConditionPathExists` hält ihn bis zum atomaren Commit von
`runtime-config.json` inert. Ein fehlgeschlagener Unit-Preflight konsumiert
deshalb keinen Enrollment-Code.

### 7. Profilgraph

Der PBP-Graph ist exakt:

```text
ssh -> ssh-gui -> vpn-pbp-de -> pbp
```

`vpn-pbp-de` steht für Mullvad Deutschland, Shadowsocks Port 443,
Auto-Connect, Lockdown und keinen normalen Firefox. Der eigenständige
`vpn`-Modus ist ein anderer Graph und darf nicht eingeschoben werden.
Examstation ist wegen seines eigenen Browser-/Authentisierungsstacks exklusiv;
Decepticon ist ein spezialisierter Worker. Beide sind deklarativ modelliert,
aber im aktuellen festen Target-Runner noch nicht zur Installation freigegeben.

### 8. SSH- und Hostkey-Vertrauen

`flow instance ssh` baut seine Argumente aus einer lokalen Instanzbindung:
`IdentitiesOnly`, kein Agent, kein X11, keine Passwortauthentisierung, nur
Ed25519, `StrictHostKeyChecking=yes`, kein DNS-/UpdateHostKeys-Fallback und eine
eigene Known-Hosts-Datei je Instanz. `--gui` fügt ausschließlich einen lokalen
Forward auf `127.0.0.1:5901` hinzu.

Der erste Hostkey wird niemals aus dem Serving-Status übernommen. Der Operator
exportiert `/etc/ssh/ssh_host_ed25519_key.pub` über die authentisierte
Providerkonsole, vergleicht den Fingerprint out-of-band und verwendet danach
den expliziten, netzwerklosen Befehl `flow instance hostkey pin`. Erst mit
diesem lokalen Pin ist SSH möglich.

Ein Statusreport darf den gemeldeten Key nur gegen den vorhandenen Pin
vergleichen; jede Abweichung stoppt hart. Eine spätere Rotation erfordert
erneut einen außerhalb von Serving verifizierten Public Key in einer regulären
Datei und `flow instance hostkey rotate`. `ssh-keyscan` ist nie ein
Vertrauensanker. Der explizite `flow test lab`-Pfad verwendet dieselben Pins
und SSH-Härtungen, aber nur eine kompilierte feste Action-Allowlist; freie
Remote-Argumente sind dort nicht möglich.

### 9. Status und Logs sind Observability, keine Autorisierung

Instances senden nur finite Zustände, Ereignisnamen und Fehlercodes. Freies
stderr verbleibt bereinigt und root-only auf der Ziel-VM. Serving bewahrt pro
Komponente höchstens 1024 sequenzierte Ereignisse auf. Die Betreiber-CLI prüft
die Bindungen erneut und verhindert Terminal-Control-Injection.

Ein Statusrequest ist beim Eingang durch die Instance Identity signiert. Die
Serving-Datenbank speichert gegenwärtig jedoch nur den validierten Statusbody,
nicht die Signaturhülle. Deshalb darf Status niemals Release, Desired State,
den ersten SSH-Hostkey oder Root-Aktionen autorisieren. Das verbleibende
Observability-Risiko ist im Threat Model ausdrücklich festgehalten.

### 10. Bootstrap-Vertrauensgrenze

Der bequeme Pfad `curl .../bootstrap | sudo sh` vertraut die zuerst geladenen
Bytes vollständig der TLS-/Serving-Identität an. Die Digest-Angabe im Header
derselben Antwort hebt diese Grenze nicht auf. Der gehärtete Pfad lädt in eine
Datei, prüft einen über einen unabhängigen Kanal erhaltenen SHA-256-Wert und
führt erst dann aus. Das authentisierte Bootstrap enthält CA, TLS-Pin sowie
Release- und Desired-State-Public-Key und lädt anschließend `flow` nur mit der
im signierten Release gebundenen Größe und Prüfsumme.

## Konsequenzen

- Ein kompromittiertes Serving kann Verfügbarkeit, Enrollment und
  Observability stören, aber ohne Operator-Signing-Key keinen neuen Root-Code
  oder Desired State autorisieren.
- Der Operator muss drei Control-/Signing-Wurzeln und die privaten SSH-Keys
  sicher und getrennt sichern. Ihr Verlust ist nicht durch Serving heilbar.
- Die schemaversionierte, gelockte JSON-Ablage reduziert die Angriffsfläche,
  begrenzt den ersten Entwurf aber auf einen einzelnen Serving-Knoten.
- Die Key-Rotation ist bewusst mehrstufig: Neue und alte SSH-Public-Keys
  überlappen, bis die Instanz die Generation bestätigt; erst danach wird der
  alte Key entfernt.
- Legacy-Shell-Installer bleiben vorübergehend Teil der internen
  Ausführungskette, nicht der öffentlichen Operator-UX.

## Noch offene Release-Gates

Diese Entscheidung beschreibt die Ziel- und implementierte Kernarchitektur,
nicht einen bereits erteilten Produktionsstatus. Vor einer Freigabe fehlen
weiterhin:

- ein echter, dokumentierter E2E-Lauf über vier ausdrücklich als disposable
  markierte VMs;
- der reale PBP-Soak von mindestens 30 Minuten einschließlich fünf
  Schließen-/Neustartzyklen und echtem VPN-Ausfall;
- der reale Vier-VM-Nachweis des implementierten automatischen Reconcile nach
  Reboot und Serving-Ausfall;
- der freigegebene feste Target-Runner für Decepticon und Examstation.

Ergebnisse und Blocker werden im
[Lab-/E2E-Runbook](../LAB-E2E-RUNBOOK.md) geführt und nicht durch lokale Mocks
als bestanden ersetzt.
