# Vier-VM-lab und E2E-qualifikation

> **in development.** der ausführende lab-pfad ist aktuell durch die
> unvollständige control-route gesperrt; außerdem fehlen optionale komponenten
> des vollständigen plattform-releases. ein lokales `make check` prüft nur
> den mitgelieferten go-kern. dieses runbook dokumentiert offene abnahmeziele.

dieses runbook ist die freigabecheckliste fuer dynamicflow. ein lokaler
testlauf ersetzt keinen nachweis auf echten vms. insbesondere gelten der
vier-VM-E2E-lauf und der PBP-soak erst als bestanden, wenn die unten genannten
artefakte aus genau einem qualifizierenden lauf vorliegen.

der gegenwaertige projektstand ist **nicht produktionsfreigegeben**: die hier
beschriebene VM-qualifikation ist noch nicht als bestanden dokumentiert.

## Sicherheitsgrenzen

- das lab-inventar darf nur instanzname, eindeutige rolle, erreichbare
  IP-adressen, SSH-benutzer, betriebssystem, pfad zum lokalen privaten
  schluessel, den out-of-band ermittelten Ed25519-hostkey-fingerprint, dessen
  explizite bestaetigung, rollenbezogene attestierungs-tokens und die
  disposable-freigabe enthalten. weder schluessel- noch beweisinhalte werden
  daraus gelesen.
- private schluesselinhalte, enrollment-secrets, mullvad-kontonummern,
  VNC-passwoerter und persona-inhalte gehoeren weder in die inventardatei noch
  in logs, tickets, screenshots oder ergebnisberichte.
- `disposable: false` ist der sichere ausgangszustand. erst eine ausdrueckliche
  freigabe des besitzers erlaubt `true` und damit destruktive negativtests oder
  neuinstallation.
- `flow` aendert keine cloud-firewalls, DNS-eintraege, provider-accounts oder
  abrechnung. solche aenderungen brauchen eine separate genehmigung.
- rohes `ssh`/`scp` ist nur fuer den erstmaligen bootstrap oder eine begruendete
  diagnose erlaubt. danach werden HTTPS-lifecycle und die expliziten,
  auditierten befehle `flow instance ssh`, `flow instance exec` sowie die feste
  action-allowlist von `flow test lab` gedogfooded.
- serving darf keine verbindung zu einer ziel-VM initiieren. die ziel-vms
  installieren und melden status ueber ausgehendes HTTPS.

## 1. privates inventar

`flow test lab` akzeptiert nur inventar-schema 2. die datei und der referenzierte
lokale private bootstrap-schluessel muessen normale, nicht verlinkte und nicht
hartverlinkte dateien im eigentum des aktuellen operators mit exakt modus
`0600` sein. der parser prueft beim privaten schluessel ausschliesslich den
absoluten, normalisierten pfad und diese metadaten. er oeffnet oder liest den
schluesselinhalt nicht. der pfad und der hostkey-fingerprint erscheinen nicht
im plan oder ergebnisbericht.

`known_hosts_file` ist kein inventarfeld mehr. der tatsaechlich von SSH
verwendete, instanzbezogene known-hosts-pin liegt im privaten flow-state. das
inventar bindet diesen pin zusaetzlich an einen ueber die providerkonsole
geprueften Ed25519-fingerprint:

```yaml
version: 2
hosts:
  - name: lab-serving
    role: serving
    address: 192.0.2.10
    ipv6: 2001:db8::10
    ssh_user: admin
    os: Debian 13
    identity_file: /ABS/PATH/lab-bootstrap-key
    host_key_fingerprint: SHA256:REPLACE_WITH_CANONICAL_43_CHAR_VALUE
    host_key_verified_out_of_band: false
    disposable: false
  - name: lab-enrollment
    role: enrollment
    address: 192.0.2.11
    ssh_user: admin
    os: Ubuntu 24.04
    identity_file: /ABS/PATH/lab-bootstrap-key
    host_key_fingerprint: SHA256:REPLACE_WITH_CANONICAL_43_CHAR_VALUE
    host_key_verified_out_of_band: false
    disposable: false
  - name: lab-pbp
    role: pbp
    address: 192.0.2.12
    ssh_user: admin
    os: Debian 13
    identity_file: /ABS/PATH/lab-bootstrap-key
    host_key_fingerprint: SHA256:REPLACE_WITH_CANONICAL_43_CHAR_VALUE
    host_key_verified_out_of_band: false
    disposable: false
  - name: lab-recovery
    role: recovery-negative
    address: 192.0.2.13
    ssh_user: admin
    os: Debian 13
    identity_file: /ABS/PATH/lab-bootstrap-key
    host_key_fingerprint: SHA256:REPLACE_WITH_CANONICAL_43_CHAR_VALUE
    host_key_verified_out_of_band: false
    disposable: false
```

die `REPLACE_...`-werte sind absichtlich keine gueltigen platzhalter. exportieren
sie `/etc/ssh/ssh_host_ed25519_key.pub` ueber die authentisierte
providerkonsole, berechnen sie den fingerprint lokal und vergleichen sie ihn
ueber einen zweiten kanal. `ssh-keyscan` ist kein vertrauensanker:

```sh
ssh-keygen -lf /ABS/PATH/provider-console-hostkey.pub -E sha256
flow instance hostkey pin NAME \
  --public-key-file /ABS/PATH/provider-console-hostkey.pub
```

ein eingetragener fingerprint bei
`host_key_verified_out_of_band: false` ist nur ein beobachteter kandidat, kein
vertrauensanker. `--plan` darf ihn lokal parsen und meldet den host als
blockiert; ein normaler lauf darf damit weder SSH starten noch mutieren. die
bestaetigung darf insbesondere nicht aus derselben ungepinnten SSH-verbindung
abgeleitet werden.

erst nach dem unabhaengigen vergleich wird genau fuer diesen host
`host_key_verified_out_of_band: true` gesetzt. der runner validiert, dass der
fingerprint des Ed25519-schluessels im flow-state exakt dem inventar entspricht.
ein abweichender, fehlender oder nicht bestaetigter pin blockiert vor dem ersten
SSH-prozess.

### Migration von inventar v1

1. aendern sie `version: 1` in `version: 2`.
2. entfernen sie jede zeile `known_hosts_file:`. die datei wird nicht mehr als
   paralleler vertrauensanker verwendet.
3. fuegen sie je host `host_key_fingerprint:` mit dem kanonischen, ueber die
   providerkonsole ermittelten wert hinzu.
4. beginnen sie mit `host_key_verified_out_of_band: false`, ohne
   `attested_gates`, und behalten sie `disposable: false` bei.
5. fuehren sie den plan aus. er bleibt erfolgreich lesbar, meldet die gates aber
   maschinenlesbar als blockiert. setzen sie bestaetigungen erst nach dem
   jeweiligen realen test.

```sh
chmod 0600 /ABS/PATH/.flow/lab.yaml /ABS/PATH/lab-bootstrap-key
flow test lab --inventory /ABS/PATH/.flow/lab.yaml --plan
flow --json test lab --inventory /ABS/PATH/.flow/lab.yaml --plan
```

der JSON-plan enthaelt `qualification_matrix`,
`blocked_non_disposable`, `blocked_hostkey_unconfirmed`,
`blocked_attestations` und `blocked_unpinned`. er startet kein SSH und keine
HTTPS-mutation. jede der vier rollen muss genau einmal vorkommen.

### Externe, explizite attestierungen

die folgenden negativtests lassen sich ohne enrollment-secret oder bewusst
manipuliertes release nicht sicher und idempotent im runner erzeugen. sie werden
nicht als automatisiert ausgegeben. nach ihrer realen durchfuehrung werden nur
die exakt rollenbezogenen tokens als kommaseparierter skalar eingetragen:

```yaml
# Nur Rolle enrollment:
attested_gates: fresh-enrollment-outbound-https,enrollment-replay-rejected,enrollment-expiry-rejected

# Nur Rolle recovery-negative:
attested_gates: signature-tamper-rejected,digest-tamper-rejected,apply-interruption-injected,runtime-upgrade-published
```

unbekannte, doppelte oder einer falschen rolle zugewiesene tokens werden
abgewiesen. eine attestierung ist eine operator-erklaerung, kein vom runner
erzeugter beweis. wer sie ohne den beschriebenen VM-test setzt, macht den lauf
ungueltig. der runner prueft danach den resultierenden zustand mit festen
aktionen: public-key-only enrollment, zwei bereinigte verifikationsfehler,
einen erfolgreich wiederaufgenommenen apply-versuch, leeres staging,
content-adressierte runtime-recovery-kopien und den echten produktions-lock.

erst unmittelbar vor dem integrierten lauf darf fuer alle vier ausdruecklich
neu aufsetzbaren hosts `disposable: true` gesetzt werden. jede mutierende feste
action und jeder begrenzte control-schritt prueft dieses gate erneut.

### Feste qualifikationsmatrix

der plan und jeder private ergebnisbericht enthalten dieselbe geordnete matrix.
nach allen lokalen gates und allen vier bindungspruefungen ist die kleinste
feste VM-sequenz:

1. gepinnter SSH-preflight aller vier rollen;
2. serving HTTPS/no-SSH-probe, ein realer vollstaendiger
   `flow start serving --plan`-no-op, zwei idempotente
   `flow start serving`-no-ops, echter dienstneustart und serving-VM-reboot
   mit erneuter HTTPS/no-SSH-probe;
3. runtime-/persistent-timer-probe aller zielrollen;
4. enrollment-restzustand mit exakt einem oeffentlichen Ed25519-key, danach
   zweistufige rotation und enrollment-VM-reboot;
5. recovery-evidenz, deterministischer `apply_busy`-konflikt am echten
   `targetapply.lock`, erfolgreicher reconcile nach freigabe und target-reboot;
6. VNC-/PBP-/mullvad-preflight, eine echte VNC-passwortrotation ueber den
   festen `flow instance secret rotate`-pfad, PBP-VM-reboot mit internem
   persona-vergleich, erneute VNC-/VPN-pruefung, 1800-sekunden-soak, fuenf
   normale neustartzyklen, echter VPN-fail-closed-/reconnect-test, feste
   forensik und erst danach ergebnisabruf;
7. signierte, ueber ausgehendes HTTPS bestaetigte revocation der recovery-VM.

jede remote-aktion besteht aus einem fest einkompilierten root-payload mit
fester SSH-argumentliste, timeout, ausgabelimit und audit vor prozessstart.
es gibt weder operator-argumente im root-payload noch eine freie
root-command-schnittstelle. kann der start-auditdatensatz nicht geschrieben
werden, wird kein SSH-prozess gestartet. serving initiiert weiterhin keine
verbindung zu einer ziel-VM.

## 2. lokale gates

diese tests muessen auf demselben commit und mit sauber protokolliertem
`git rev-parse HEAD` laufen. ein schmutziger working tree wird nicht bereinigt;
die getesteten diffs werden als teil des nachweises erfasst.

```sh
make check && make component-static && make optional-component-static
./ssh/tests/static-checks.sh
./vpn/tests/static-checks.sh
./pbp/tests/static-checks.sh
./examstation/tests/static-checks.sh
./examstation/tests/security-static-checks.sh
./examstation/tests/test-sshd-policy.sh
./serving/tests/mfa-static-checks.sh
./serving/tests/provision-static-checks.sh
./serving/tests/release-set-checks.sh
./serving/tests/release-flow.sh
```

zusaetzlich wird derselbe release-set zweimal mit identischer generation,
demselben release-signer und identischen eingaben gebaut. set-ID,
manifestinhalt und artefakt-digests muessen uebereinstimmen. bei verschiedenen
test-signern werden nur der signierte manifestinhalt und die artefakte
verglichen, nicht key-ID oder signaturbytes. die durch `make check` abgedeckten
artefakt-/signatur-tampertests muessen mit exitcode 5 (`verify`) scheitern. nie
das aktive set fuer einen manuellen negativtest manipulieren.

## 3. rollen und pflichtszenarien

| rolle | primaerer nachweis |
| --- | --- |
| `serving` | idempotente bereitstellung, signierte atomare releases, neustart, kein ausgehendes SSH |
| `enrollment` | ausschliesslich ausgehendes HTTPS, einmaligkeit/expiry, key-installation, gepinntes SSH |
| `pbp` | profilgraph, VNC nur loopback, deutscher mullvad-PBP-modus, 30-minuten-soak, neustarts, fail-closed |
| `recovery-negative` | signaturfehler, abbruch/resume, paralleler lauf, rollback/sicherer zustand, reboot |

### Serving-VM

1. stellen sie ein vorher lokal verifiziertes release-set und ausschliesslich
   die drei public keys bereit, wie im [quickstart](QUICKSTART.md) beschrieben.
2. führen sie `flow start serving --plan` und danach `flow start serving` aus.
3. wiederholen sie denselben mutierenden befehl. es duerfen weder TLS-identitaet
   noch aktive generation oder public-key-inhalte unbemerkt wechseln.
4. pruefen sie `flow status serving`, `flow logs serving` und den systemd-status.
5. starten sie den serving-dienst und anschliessend die VM neu. enrollment,
   manifestabruf und statusannahme muessen danach wieder funktionieren.
6. verifizieren sie den aktiven `current`-zeiger und jedes artefakt erneut.
7. erfassen sie waehrend der ziel-VM-szenarien mit host-firewall- oder
   socket-audit, dass serving keine ausgehende verbindung zu port 22 der drei
   instanzen initiiert. der nachweis darf keine paketnutzlast oder secrets
   enthalten.

die bereitstellung und das externe socket-audit bleiben vorbereitende
operator-schritte. im integrierten lauf fuehrt der runner danach selbst den
festen HTTPS-/no-SSH-probe, einen echten neustart von
`dynamicflow-serving.service`, einen idempotenten zweiten start, den reboot der
serving-VM und den erneuten HTTPS-/no-SSH-probe aus.

fuer dieses lab hat die serving-VM bewusst eine **lab-only doppelrolle**. nach
der serving-provisionierung wird derselbe disposable host zusaetzlich als
`ssh`-instanz mit exakt dem inventarnamen enrolled:

```sh
flow enroll create --name lab-serving --profile ssh \
  --host 192.0.2.10 --ssh-user admin --ttl 15m
```

konsumieren sie dieses enrollment aus der providerkonsole wie im quickstart,
exportieren/pinnen sie anschließend den hostkey explizit und pruefen sie den
status. das dient nur dazu, alle spaeteren restart-/audit-actions des lab-
runners ueber denselben gepinnten flow-SSH-pfad zu dogfooden. es macht serving
nicht zum SSH-initiator: der `dynamicflow-serving`-prozess oeffnet weiterhin
keine verbindung zu ziel-vms. diese doppelrolle ist keine empfehlung fuer
einen produktions-serving-knoten.

auf jeder ziel-VM muss vor den profiltests der feste timer nachgewiesen werden:

```sh
flow instance exec INSTANCE -- sudo systemctl is-enabled \
  dynamicflow-instance-reconcile.timer
flow instance exec INSTANCE -- sudo systemctl is-active \
  dynamicflow-instance-reconcile.timer
```

sein service darf nur den festen `instance-runtime reconcile`-one-shot
enthalten. nach einem ziel-VM-reboot muss `Persistent=true` eine verpasste
generation ohne eingehendes SSH nachholen; ein manueller reconcile zaehlt nicht
als beleg fuer dieses gate.

### Frische enrollment-VM

1. erzeugen sie eine instanz mit kurzem enrollment und eigenem instanz-key:

   ```sh
   flow enroll create --name lab-enrollment --profile ssh \
     --host 192.0.2.11 --ssh-user admin --ttl 15m
   ```

2. fuehren sie den gehaerteten bootstrap aus dem quickstart von der
   providerkonsole beziehungsweise dem vorhandenen basissystem aus. secret und
   ID werden nur verdeckt ueber TTY/stdin eingegeben.
3. wiederholen sie exakt dasselbe enrollment. der replay muss abgewiesen
   werden. erzeugen sie separat einen sehr kurzlebigen code und weisen sie nach,
   dass er nach ablauf nicht mehr nutzbar ist.
4. pruefen sie auf der VM, dass nur der erwartete public key in
   `authorized_keys` liegt. suchen sie ausschliesslich nach dateinamen und
   public-key-fingerprints; geben sie niemals einen privaten key aus.
5. exportieren sie `/etc/ssh/ssh_host_ed25519_key.pub` ueber die authentisierte
   providerkonsole, vergleichen sie den fingerprint out-of-band und pinnen sie
   genau diese lokale datei. erst danach status und SSH pruefen:

   ```sh
   flow instance hostkey pin lab-enrollment \
     --public-key-file /ABS/PATH/lab-enrollment-hostkey.pub
   flow instance status lab-enrollment
   flow instance ssh lab-enrollment
   flow instance exec lab-enrollment -- id
   ```

6. speichern sie bereinigte belege fuer den erfolgreichen frischen bootstrap,
   den abgewiesenen replay und den abgewiesenen abgelaufenen code. erst dann
   tragen sie die drei enrollment-tokens unter `attested_gates` ein.
7. lassen sie diese instanz aktiv. der integrierte runner prueft vor der
   rotation die secretfreie runtime-konfiguration, exakt eine Ed25519-zeile in
   `authorized_keys` und das fehlen ueblicher privater SSH-key-dateien. danach
   fuehrt er selbst die zweistufige rotation mit zwei HTTPS-acknowledgements
   und den reboot-/resume-test aus.
8. erfassen sie am zielhost, dass bootstrap, installation und status nur
   ausgehendes HTTPS zu serving benoetigten. die enrollment-VM wird vor dem
   integrierten lauf nicht revoziert; der feste revocation-test verwendet am
   ende ausschliesslich die recovery-VM.

### SSH-GUI-/PBP-VM

1. enrollen sie `--profile pbp` und verifizieren sie vor der mutation den plan:

   ```sh
   flow enroll create --name lab-pbp --profile pbp \
     --host 192.0.2.12 --ssh-user admin --ttl 15m
   flow instance apply lab-pbp --profile pbp --plan
   flow instance apply lab-pbp --profile pbp
   ```

2. der status muss genau `ssh -> ssh-gui -> vpn-pbp-de -> pbp` zeigen. der
   eigenstaendige firefox-modus des profils `vpn` darf nicht installiert sein.
3. pruefen sie, dass `malwarelab` unprivilegiert und gesperrt ist, VNC nur an
   loopback `5901` lauscht und clipboard aus ist. oeffnen sie die sitzung nur
   ueber:

   ```sh
   flow instance ssh lab-pbp --gui --local-port 5901
   ```

   der integrierte runner rotiert danach das VNC-passwort einmal ueber exakt
   `flow instance secret rotate lab-pbp --secret vnc`. der neue wert wird nur
   intern validiert und weder in den lab-report noch in dessen auditfelder
   uebernommen; der integrierte lauf unterdrueckt auch seine normale
   terminalausgabe. falls spaeter interaktiver lab-zugriff erforderlich ist,
   darf der betreiber den wert separat und bewusst mit
   `flow instance secret reveal lab-pbp --secret vnc` anzeigen. er darf nicht
   in inventar oder evidenzdateien gespeichert werden.

4. pruefen sie mullvad deutschland, shadowsocks-port 443, lockdown und
   auto-connect. ein relaywechsel berlin/frankfurt darf die persona nicht
   ersetzen. egress-pruefungen muessen deutschland bestaetigen; bei falschem
   oder unbekanntem egress darf PBP nicht starten.
5. starten sie PBP aus dem desktop-eintrag, schliessen sie es normal und starten
   sie es mindestens fuenfmal erneut. wiederholen sie einen zyklus nach
   erzwungenem browserabbruch. es duerfen keine verwaisten camoufox-/playwright-
   prozesse oder dauerhaft gehaltenen `browser.lock`-dateisperren bleiben.
6. simulieren sie einen kurzen mullvad-pruefendpunkt-/relay-ausfall. der launcher
   muss begrenzt mit backoff warten und einen sichtbaren fehler melden. bei
   verlorenem oder falschem egress bleibt der browser geschlossen und lockdown
   aktiv; es gibt keinen blinden auto-restart. der feste helper akzeptiert den
   reconnect erst, wenn ein verifizierter deutscher mullvad-egress von der
   unmittelbar zuvor im speicher gehaltenen baseline abweicht. weder alte noch
   neue IP-adresse werden in ergebnis, audit oder journal geschrieben. danach
   muss PBP real starten, per normalem `WM_DELETE` sauber schliessen und den
   browser-lock in einem weiteren start erneut belegen koennen.
7. der integrierte runner erfasst inode, digest, groesse und stabile
   persona-felder nur als fluechtigen vergleichswert, startet die PBP-VM neu
   und verlangt nach runtime-, VNC- und VPN-recovery exakt denselben wert.
   weder einzelwerte noch vergleichsdigest gelangen in das portable ergebnis.
   erst danach startet der 30-minuten-harness; PBP muss sicher erneut starten.

die technischen pfade und die abgrenzung der bereits lokal reproduzierten
ursache stehen in [PBP-P0-ursache und beweisplan](PBP-INCIDENT.md).

### Recovery-/negativ-VM

diese rolle darf fuer signatur-/digest-negativtests, prozessabbruch, runtime-
upgrade und neuaufsetzen nur nach ausdruecklicher freigabe verwendet werden.
beginnen sie trotzdem mit `disposable: false`; erst der finale integrierte lauf
verlangt `true`.

1. enrollen und pinnen sie die rolle mit einem eigenen instanz-key. halten sie
   das letzte verifizierte release und den providerkonsolenzugriff fuer
   recovery bereit.
2. bieten sie in einem isolierten, nicht produktiven testlauf je ein falsch
   signiertes desired state beziehungsweise manifest und ein artefakt mit
   falschem digest an. keine variante darf aktiviert werden. beide versuche
   muessen im bereinigten journal der festen
   `dynamicflow-instance-reconcile.service` als `verification` enden. aktivieren
   sie nie ein manipuliertes release-set auf einem produktiven serving-knoten.
3. publizieren sie danach eine gueltige neue generation. unterbrechen sie einen
   profil-apply nach dem persistenten `applying`-checkpoint und lassen sie den
   unveraenderten one-shot erneut laufen. der gleiche journalplan muss komplett
   werden und mindestens fuer eine phase `attempts >= 2` behalten; staging muss
   leer sein. ein abbruch nur vor erstellung des apply-journals reicht fuer
   dieses gate nicht.
4. publizieren sie ein gueltiges release mit einer neuen `flow`-runtime. der
   alte prozess muss nach atomarer aktivierung vor profilphasen enden und der
   persistent-timer mit der neuen binary fortsetzen. unter
   `apply/runtime-recovery` muessen danach mindestens die content-adressierte
   aktive runtime und eine geschuetzte vorgaengerkopie liegen.
5. pruefen sie einen unerwarteten SSH-hostkey-wechsel. `flow` muss vor SSH
   stoppen. eine rotation ist erst nach unabhaengiger konsolenpruefung erlaubt:

   ```sh
   flow instance hostkey rotate lab-recovery \
     --public-key-file /ABS/PATH/verified-hostkey.pub
   ```

6. tragen sie erst jetzt die vier recovery-tokens unter `attested_gates` ein.
   der runner liest anschliessend nur bounded restzustandsbelege: kanonische
   root-eigene journale, mindestens einen wiederaufgenommenen versuch, leeres
   staging, gehashte runtime-recovery-dateien und mindestens zwei bereinigte
   verifikationsereignisse. rohes journal oder runtimebytes gelangen nicht in
   den report.
7. der runner erzeugt die parallelitaetsprobe selbst deterministisch: er haelt
   den echten `targetapply.lock`, verlangt beim festen konkurrierenden
   `instance-runtime reconcile` exakt `apply_busy`, gibt den lock frei und
   verlangt dann einen erfolgreichen reconcile. danach folgen target-reboot,
   resume und als letzter gesamtschritt die signierte fail-closed revocation
   mit HTTPS-status- und log-acknowledgement.

## 4. qualifizierender PBP-soak

im vollständigen lauf startet `flow test lab` diesen soak selbst als zwei
begrenzte transiente systemd-units: den harness als `malwarelab` in der
tatsächlichen XFCE/VNC-session und einen root-eigenen, socketgebundenen
mullvad-disconnect-/reconnect-helper. es erfindet weder `DISPLAY` noch den
session-bus, akzeptiert nur den festen harness aus diesem repository und
pollt höchstens 60 minuten. aufruf nach allen manuellen vorbedingungen:

```sh
flow test lab --inventory /ABS/PATH/.flow/lab.yaml
```

die transienten units heißen `dynamicflow-lab-pbp-soak.service` und
`dynamicflow-lab-pbp-vpn-trigger.service`; ihre stagingdateien liegen nur unter
`/run/dynamicflow-lab-pbp-*`. der helper authentisiert den lokalen aufrufer per
`SO_PEERCRED`, erlaubt exakt `disconnect -> connect`, hat eine harte deadline
und akzeptiert den reconnect nur mit einem anderen verifizierten deutschen
egress. die beiden IP-adressen bleiben ausschliesslich in seinem fluechtigen
speicher. er versucht bei abbruch die verbindung wiederherzustellen. ein
abgebrochener lauf bleibt dennoch `BLOCKED`; unit-journal und mullvad-egress
über die providerkonsole prüfen, bevor er wiederholt wird.

die folgenden schritte sind der isolierte manuelle diagnoseweg. er darf für
eine PBP-wiederholung genutzt werden, ersetzt aber nicht die übrigen phasen des
integrierten vier-VM-laufs.

die harness-datei wird nach dem bootstrap ueber den eigenen expliziten
exec-pfad uebertragen. dadurch wird kein allgemeiner resident-agent eingefuehrt:

```sh
flow instance exec lab-pbp -- \
  sudo -n -u malwarelab install -d -m 0700 \
  /home/malwarelab/.local/lib/dynamicflow-tests

flow instance exec lab-pbp -- \
  sudo -n -u malwarelab dd \
  of=/home/malwarelab/.local/lib/dynamicflow-tests/pbp-vm-soak.py \
  status=none < pbp/tests/pbp-vm-soak.py

sha256sum pbp/tests/pbp-vm-soak.py
flow instance exec lab-pbp -- \
  sha256sum /home/malwarelab/.local/lib/dynamicflow-tests/pbp-vm-soak.py
flow instance exec lab-pbp -- \
  sudo -n -u malwarelab chmod 0700 \
  /home/malwarelab/.local/lib/dynamicflow-tests/pbp-vm-soak.py
```

vergleichen sie die beiden digests lokal, ohne shellsubstitution in einem
automatischen report. starten sie anschliessend in einem terminal der realen
XFCE/VNC-sitzung als `malwarelab`; `DISPLAY` und session-bus duerfen nicht
erfunden oder aus einer anderen sitzung uebernommen werden:

```sh
/home/malwarelab/.local/lib/dynamicflow-tests/pbp-vm-soak.py \
  --duration-seconds 1800 \
  --normal-cycles 5 \
  --exercise-vpn-failure \
  --disposable-network-test
```

ein qualifizierender lauf hat mindestens 1800 sekunden, mindestens fuenf
normale schliessen-/neustart-zyklen und beide expliziten VPN-negativtest-flags.
sein ergebnis muss ausserdem `real_relay_switch`,
`egress_identity_changed` und `restart_after_relay_switch` als wahr
ausweisen; IP-adressen selbst sind im ergebnisschema verboten.
exitcode 0 bedeutet `PASS`, 1 `FAIL`, 2 `BLOCKED` und 130 unterbrechung. nur
`PASS` zaehlt. `BLOCKED`, ein verkuerzter lauf oder ein lauf ohne echte
desktop-session ist kein erfolg.

zu pruefende lokale pfade auf der PBP-VM:

- persona: `/etc/toolkit/pbp-persona.json`
- profil: `/home/malwarelab/.local/share/toolkit-pbp/profile`
- browser-lock: `/home/malwarelab/.local/share/toolkit-pbp/browser.lock`
- laufzeitlogs:
  `/home/malwarelab/.local/state/dynamicflow/pbp/logs/runtime-*.jsonl`

logs muessen modus `0600` haben, bereinigt sein, maximal acht rotierte dateien
behalten und je datei maximal 4 MiB gross sein. der integrierte runner prueft
VNC-/XFCE- und mullvad-invarianten vor dem soak. der harness prueft waehrend
der zyklen browserprozess und exaktes profil, playwright-endklassifikation,
lock-freigabe, persona-stabilitaet, mullvad-egress, sichtbare desktop-fehler
und bereinigtes runtime-stderr. unmittelbar nach ende des soaks und zwingend
vor dem ergebnisabruf sammelt eine separate feste forensik-action zusaetzlich
begrenzte, kanonische metadaten, zaehler und digests fuer XFCE/VNC,
browser-/playwright-prozesse, profil/locks, persona-dateimetadaten,
runtime-events, AppArmor-denials, kernel-OOM/segfault/killed-ereignisse,
coredumps und die endzustaende der transienten units. rohes journal, stderr,
persona-inhalt und coredump-inhalt verlassen die VM nicht. fehlende,
inkonsistente oder unkanonische forensik macht den lauf ungueltig; das bereits
erzeugte soak-ergebnis wird trotzdem erst danach sicher abgerufen und fuer die
diagnose erhalten. eine konkrete ursachenbehauptung braucht weiterhin die im
`PBP-INCIDENT.md` beschriebene korrelation.

## 5. evidenzpaket und ergebnis

der integrierte runner schreibt bei PASS, FAIL oder BLOCKED einen privaten
report nach `$FLOW_HOME/lab/results/<UTC>-<nonce>-report.json`. sobald ein
PBP-ergebnis vorliegt, speichert er dessen streng validierte bytes daneben als
`...-pbp.json` und bindet ihren SHA-256-digest in den report. verzeichnisse sind
`0700`, dateien `0600`; die CLI nennt den konkreten pfad und bei fehlern die
nächste handlung. das PBP-schema ist auf 1 MiB begrenzt und verbietet
secretartige felder, IP, URL, account und persona-werte.

der report enthaelt auch die geordnete `qualification_matrix` und die streng
validierte PBP-forensik samt digest und remote-bytezahl. vor dem start
blockierte inventar-, disposable-, attestierungs- oder pin-gates erzeugen
absichtlich noch keinen laufreport: `--plan` ist dafuer die
maschinenlesbare, verbindungsfreie vorpruefung. sobald der start-audit
geschrieben und der runner begonnen hat, werden PASS, FAIL und BLOCKED als
privater report gesichert.

zusaetzliche nachweise in einem mode-`0700`-verzeichnis ausserhalb des
repositories speichern. vor weitergabe IP-adressen, benutzernamen, token,
secrets, private/public key-zeilen, persona-inhalte und ungefiltertes stderr
bereinigen. public-key-fingerprints duerfen nur dann in einen bericht, wenn sie
fuer den nachweis erforderlich und nicht mit einer realen instanz verknuepfbar
sind; persona-ID und -digest bleiben immer lokal.

das abschlussprotokoll enthaelt mindestens:

- commit-ID sowie hash der uncommitteten diffs;
- `flow --version` beziehungsweise build-ID und release-generation;
- start-/endzeit in UTC, VM-rollen und betriebssysteme;
- jeden ausgefuehrten befehl ohne secretwerte;
- exitcode und bereinigten logpfad je phase;
- release-/manifest-digests und ergebnis der reproduzierbarkeitspruefung;
- enrollment-replay-/expiry-, key-rotation-/revocation- und hostkey-pin-nachweis;
- netzwerkbeleg fuer ausgehendes HTTPS und fehlendes serving-initiierter SSH;
- PBP-harness-ergebnis, laufdauer, zahl der zyklen und VPN-negativtest;
- qualifizierte `persona unchanged`-pruefung vor/nach lauf und reboot, ohne
  persona-inhalt, persona-ID oder digest im uebertragbaren bericht;
- alle abweichungen, verbleibenden risiken und konkrete recovery-schritte.

der freigabestatus bleibt bis zur realen ausfuehrung:

| gate | aktueller dokumentierter stand |
| --- | --- |
| lokale unit-/race-/static-tests | fuer den finalen commit erneut auszufuehren |
| reproduzierbarer signierter release | auf finalem commit nachzuweisen |
| vier rollen auf echten vms | **nicht ausgefuehrt** |
| enrollment/replay/expiry auf VM | **nicht ausgefuehrt** |
| serving-neustart und kein ausgehendes SSH | **nicht ausgefuehrt** |
| PBP-soak mindestens 30 minuten | **nicht ausgefuehrt** |
| fuenf PBP-schliessen-/neustart-zyklen | **nicht ausgefuehrt** |
| VPN-fail-closed/relaywechsel | **nicht ausgefuehrt** |
| recovery-/rollback-/reboot-szenarien | **nicht ausgefuehrt** |

erst wenn jede zeile durch ein verlinktes, bereinigtes evidenzartefakt ersetzt
ist, darf der lauf im abschlussbericht als bestanden bezeichnet werden.
