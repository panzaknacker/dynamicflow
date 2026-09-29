# Toolkit PBP

## Normaler weg: `./pbp-m`

der normale einstieg ist lokal aus diesem projektverzeichnis:

```sh
./pbp-m
```

ohne argumente erscheint ein menü. auswahl `1` ist die vorgabe und richtet
eine neue disposable PBP-VM vollständig ein; auswahl `2` verbindet eine
bereits eingerichtete PBP-VM. flow/serving und ein aus dem netz gepipeter
shell-installer gehören nicht zu diesem normalweg.

> **der aktuelle browserstand ist nur test-ONLY.** das normale security-
> release-gate ist wegen der veralteten camoufox-/gecko-baseline blockiert.
> `pbp-m` zeigt diese evidenz vor jedem neuen setup an und kann ausschließlich
> einen klar markierten disposable-testbuild zulassen. diesen nur auf einer
> wegwerf-VM und ohne sensible browser-accounts, passwörter oder daten
> verwenden. die zustimmung ändert weder pins noch freigabepolicy.

vor dem start wird beim beliebigen cloud-provider eine neue wegwerf-VM
angelegt:

- debian 12+ oder ubuntu 24.04+, `amd64` oder `arm64` und systemd; falls das
  image cloud-init verwendet, muss dessen initialisierung abgeschlossen sein;
- eine literale öffentliche IPv4-adresse;
- ein normaler, nicht-root SSH-administrator, standardmäßig `ubuntu`, mit
  passwordlosem `sudo` und dem öffentlichen teil des lokal gewählten keys;
- eine echte, vom VM-ingress unabhängige serielle/KVM-/VNC-konsole für
  host-key-prüfung und recovery;
- ausgehender zugriff zunächst unverändert beziehungsweise erlaubt, damit
  paketinstallation, DNS, HTTPS und mullvad-shadowsocks auf port 443
  funktionieren.

die lokale arbeitskopie muss dieses PBP-projekt, das benachbarte
SSH-/GUI-projekt und die gepinnten vendor-artefakte enthalten. außerdem werden
die aktuelle öffentliche IPv4-adresse des clients und eine gültige
mullvad-accountnummer benötigt.

### Interaktiver setup-ablauf

1. menüpunkt `1` wählen. `pbp-m` fragt die öffentliche VM-IP beziehungsweise
   `USER@IP`, wählt einen sicher validierten privaten key aus `~/.ssh`, fragt
   exakt `IP für Access:` und hängt ausschließlich `/32` an.
2. eine persona für die ganze wegwerf-VM wählen:
   `basic` (4 threads/intel HD 400), `performance` (8 threads/GTX 980) oder
   `workstation` (12 threads/intel HD). alle verwenden `1600x900`; ein
   späterer klassenwechsel erfordert eine neue VM.
3. das lokale browser-sicherheitsgate prüfen. beim derzeit blockierten
   release zeigt `pbp-m` die test-ONLY-warnung und verlangt eine gesonderte
   zustimmung für den disposable-testbuild.
4. den angezeigten finalen cloud-firewall-zustand herstellen und die einfache
   frage am kontrollierenden terminal mit `y` bestätigen. `pbp-m` verändert
   selbst keine cloud-API.
5. standardmäßig bietet `pbp-m` an, den von der VM angebotenen
   Ed25519-SSH-host-key über die unabhängige providerkonsole zu vergleichen.
   dort ausführen:

   ```sh
   sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
   ```

   nur den dort angezeigten `SHA256:...`-fingerprint übernehmen. diese prüfung
   ist empfohlen, aber optional: mit `n` wird der beobachtete schlüssel als
   TOFU-pin gespeichert. dann kann ein angreifer beim ersten kontakt nicht
   ausgeschlossen werden. der pin wird privat unter
   `~/.ssh/pbp-m-known-hosts/` gespeichert und später automatisch
   wiederverwendet. beim setup sind `--known-hosts DATEI` und
   `--hostkey-fingerprint SHA256:...` alternative vertrauensanker und dürfen
   nicht miteinander kombiniert werden.
6. `pbp-m` öffnet einen gepinnten SSH-provisioning-kanal, prüft betriebssystem,
   architektur, systemd und `sudo` und wartet ein vorhandenes cloud-init ab.
   danach baut es SSH-/GUI- und PBP-artefakt **lokal**, prüft deren digests und
   lädt nur diese artefakte sowie den öffentlichen key in ein privates
   temporäres verzeichnis der VM. der private key wird nie hochgeladen.
7. SSH und die ausschließlich getunnelte GUI werden installiert und gehärtet.
   der gewählte public key ersetzt dabei die administrativen
   `authorized_keys`; anschließend muss eine frische, vom gehaltenen
   provisioning-kanal unabhängige SSH-anmeldung funktionieren.
8. danach folgen mullvad deutschland, shadowsocks port 443, auto-connect,
   lockdown und PBP. falls noch kein mullvad-account angemeldet ist, wird die
   accountnummer verdeckt am terminal abgefragt. nach der installation prüft
   `pbp-m` erneut eine frische SSH-anmeldung sowie persona, VPN-policy,
   PBP-launcher, VNC-dienst und ausschließlich lokalen VNC-listener.
9. zum schluss erscheinen persona und buildstatus. direkt danach zeigt ein
   eigener abschlussblock das erzeugte VNC-passwort pro setup-lauf genau einmal
   zusammen mit `127.0.0.1:5901 -> VM 127.0.0.1:5901`. sofern nicht `--no-open`
   gewählt wurde, prüft `pbp-m` zuvor den lokalen tunnelport und hält
   anschließend den gehärteten SSH-tunnel im vordergrund geöffnet. mit
   `--no-open` wird kein tunnel gestartet; deshalb werden weder connector noch
   lokaler tunnelport geprüft.

jetzt einen lokalen VNC-viewer mit `127.0.0.1::5901` verbinden; manche viewer
erwarten `127.0.0.1:5901`. das angezeigte VNC-passwort vertraulich behandeln.
die mandatory-policy verweigert client-seitiges desktop-resizing, damit das
fingerprint-display auch nach dem verbinden stabil `1600x900` bleibt.
TCP 5901 wird niemals an der öffentlichen VM-IP geöffnet. providerkonsole und
ursprünglichen zugang erst schließen, nachdem die frischen SSH-prüfungen und
der tunnel erfolgreich waren. nach ende des manuellen zugriffs erinnert
`pbp-m` daran, die `/32`-cloud-regel wieder zu entfernen.

der vollständige bedien- und recovery-ablauf steht in `PBP-M.md`.

der quellstand trägt die komponentenversion `v0.1.9`. er ist derzeit jedoch
**nicht als neuer browser-release freigegeben**: am 2026-07-27 verlangte
mozilla als security-baseline firefox/gecko 153.0, während der PBP-lock noch
camoufox `150.0.2-beta.25` und selbst der zuletzt geprüfte camoufox-checkpoint
nur `152.0.4-beta.28` verwendet. die review-policy steht deshalb absichtlich
auf `blocked`; `browser-maintenance.py release` und damit `make-release.sh`
brechen fail-closed ab. ein vorhandener versionsstring ist keine aussage,
dass dieser browser-pin aktuell sicher oder ausrollbar ist.

im normalen ablauf richtet `pbp-m` eine neue debian-/ubuntu-wegwerf-VM ein,
härtet SSH und die getunnelte GUI und installiert den interaktiven
privacy-browser:

- der host bleibt linux. camoufox liefert eine aus seinen gepinnten presets
  abgeleitete windows-firefox-persona an websites; PBP behauptet nicht, den
  linux-host selbst in windows zu verwandeln.
- mullvad wird systemweit auf deutschland gestellt, über shadowsocks auf
  port 443 verbunden und mit auto-connect plus lockdown abgesichert.
- der browser verwendet keinen eigenen proxy. WebRTC erhält ausschließlich
  die aktuell geprüfte mullvad-IPv4-adresse.
- die adressleiste verwendet die bereits gebündelte DuckDuckGo-engine;
  netzwerk-suchvorschläge sind abgeschaltet.
- sprache und zeitzone sind konsistent `de-DE` und `Europe/Berlin`.
- bei der installation wird genau eine der drei festen persona-klassen
  `basic`, `performance` oder `workstation` gewählt. preset, fonts, voices,
  canvas-/audio-/font-seeds, WebGL und firefox-prefs werden lokal für diese
  wegwerf-VM materialisiert und danach zusammen mit ihrem browserprofil
  innerhalb der VM stabil wiederverwendet.
- es gibt keine VM-übergreifende persona-datenbank, keine kollisionsabfrage
  und keinen session-abgleich mit einem externen dienst. sitzungsspezifische
  netzidentität wie die mullvad-ausgangs-IP wird nicht in der stabilen persona
  gespeichert.
- uBlock origin ist als exakt gehashte XPI bestandteil des privaten releases
  und wird auf der VM sicher in camoufox' erforderliches add-on-verzeichnis
  mit geprüftem `manifest.json` extrahiert.
- der start ist sichtbar und interaktiv. playwright verwaltet nur den
  browserprozess; PBP führt keine klicks, navigation, `evaluate`-skripte,
  WebDriver-ports oder headless-automation aus.

## Aktueller freigabestatus

das offline-gate vergleicht repository, tag, vollständigen commit, assetnamen,
urls, SHA-256-digests, python-wrapper und gecko-baseline mit einer kurzlebigen
review-policy. es gibt keinen umgebungsvariablen-bypass und kein automatisches
browserupdate. `browser-maintenance.py audit` liest nur aktuelle offizielle
metadaten; pins und policy müssen anschließend bewusst gemeinsam geprüft und
geändert werden. der genaue ablauf steht in `CAMOUFOX-MAINTENANCE.md`.

solange der oben genannte gecko-rückstand besteht, ist ein lokaler unit- oder
static-test-PASS ausdrücklich keine releasefreigabe. erst ein neuer,
vollständig geprüfter pin, ein `approved`-review und die unten beschriebene
qualifikation auf einer echten wegwerf-VM dürfen diesen status ändern.

## Sekundär: bestehende PBP-VM verbinden

menüpunkt `2` oder `./pbp-m --connect` öffnet den GUI-tunnel zu einer bereits
eingerichteten PBP-VM, ohne sie erneut zu provisionieren. der wrapper prüft
den exakten vorhandenen host-key-pin, lässt den privaten key aus `~/.ssh`
wählen, prüft den freien lokalen tunnelport und fragt die globale
IPv4-access-adresse ab. ein beim setup verwalteter pin unter
`~/.ssh/pbp-m-known-hosts/` wird automatisch gefunden. IPv6, breite netze und
DNS-ziele werden abgewiesen; PBP ist systemweit IPv4-only.

### Optionaler adapter nur für bestehende vms

mit einem konfigurierten
`PBP_M_WHITELIST_HELPER=/pfad/zum/provider-adapter` fordert der wrapper einen
zeitlich begrenzten firewall-lease an. erst nach einer exakt passenden
JSON-bestätigung startet er den vorhandenen GUI-connector mit minimaler
umgebung. bei normalem ende, fehler oder behandeltem signal gibt er den lease
wieder frei; eine vom provider erzwungene TTL bleibt pflicht, weil kein
lokaler cleanup einen `SIGKILL` oder hostausfall abfangen kann.

das repository kennt die konkrete provider-firewall nicht und enthält daher
absichtlich keinen auf einen anbieter zugeschnittenen cloud-adapter. der
verbindliche `acquire`-/`release`-vertrag und das lease-schema stehen in
`PBP-M.md`; ein adapter muss das tatsächlich verwendete firewallobjekt
eindeutig an die ziel-IP binden.

### Lockout-sichere manuelle cloud-freigabe

cloud-firewall und PBP-bootstrap sind zwei getrennte ebenen. der entfernte
bootstrap ändert keine provider-firewall und kann weder angehängte
security-groups noch netzwerk-acls von innen zuverlässig verifizieren. eine
bestätigungsfrage am ende des remote-installers würde daher nur einen klick,
aber keinen erreichbaren SSH-pfad beweisen. die manuelle bestätigung gehört
stattdessen lokal in `pbp-m`: nach dessen lokalen prüfungen und unmittelbar
vor dem aufbau einer **neuen** verbindung.

für eine manuelle freigabe gilt diese reihenfolge:

1. die bestehende SSH-sitzung geöffnet lassen und zusätzlich die unabhängige
   provider-konsole beziehungsweise den dokumentierten recovery-zugang
   bereithalten. ein browser-SSH-gateway ist nur dann ein recovery-zugang,
   wenn es den VM-ingress und dessen firewallpfad nachweislich umgeht; sicherer
   ist eine echte serielle/KVM-/VNC-konsole. niemals die einzige
   funktionierende sitzung zuerst beenden.
2. in `pbp-m` die literale öffentliche IPv4-zieladresse, den SSH-key und die
   globale IPv4-access-adresse bestätigen.
3. die von `pbp-m` angezeigte einzelregel **additiv** eintragen: eingehend nur
   TCP zum tatsächlichen SSH-port, quelle exakt `ACCESS-IP/32`, ziel
   ausschließlich die ausgewählte VM. die regel wirksam anwenden und die
   provider-aktivierung abwarten, bevor eine breitere altregel entfernt wird.
4. alle für die VM wirksamen ebenen prüfen: direkt angehängte firewall,
   security-group, projekt-/netzwerk-firewall und gegebenenfalls
   netzwerk-ACL und host-firewall. eine erlaubnis in nur einer ebene hilft
   nicht, wenn eine weitere ebene den pfad verwirft. ein mit anderen vms
   geteiltes regelobjekt nicht unbesehen ändern; gegebenenfalls ein dediziertes
   objekt für diese VM verwenden. keine freigabe für `0.0.0.0/0`, einen
   größeren quellbereich oder IPv6 verwenden.
5. ist die cloud-firewall ausgeschaltet oder noch nicht an die VM gebunden,
   existiert keine cloud-allowlist und das gate darf nicht allein deshalb
   bestätigt werden. zuerst das vollständige regelwerk einschließlich
   erforderlichem outbound vorbereiten, dann mit offener provider-konsole
   aktivieren beziehungsweise anhängen. je nach plattform kann bereits dieser
   schritt eine bestehende verbindung beenden.
6. TCP-port `5901` niemals öffentlich freigeben. der grafische zugriff bleibt
   ausschließlich im SSH-tunnel.
7. ausgehende cloud-regeln während mullvad- und PBP-installation nicht
   nebenbei verschärfen. DNS, HTTPS, der konfigurierte
   mullvad-shadowsocks-transport auf port 443 sowie der anschließend
   aufgebaute tunnel müssen den provider verlassen können. eine
   providerseitige default-deny-egress-policy wird separat anhand der
   tatsächlichen plattformsemantik und in einer wegwerf-VM qualifiziert.
   stateful firewalls benötigen üblicherweise keine eigene rückregel;
   stateless acls dagegen den vom provider dokumentierten minimalen
   TCP-rückpfad. `pbp-m` rät diese semantik nicht.
8. vor der bestätigung jede ältere, breitere oder überlappende SSH-freigabe in
   **allen** wirksamen ebenen entfernen beziehungsweise deaktivieren, während
   die bestehende SSH-sitzung und die provider-konsole offen bleiben. nur
   dieser endgültige effektive inbound-zustand kann qualifiziert werden; eine
   neue verbindung bei weiterhin aktiver breiter altregel würde die
   einzelregel nicht beweisen.
9. den endgültigen cloud-zustand vollständig speichern beziehungsweise
   anwenden und erst dann das manuelle gate in `pbp-m` bestätigen. eine
   bestätigung ersetzt keinen verbindungstest. je nach provider kann das
   entfernen einer regel auch eine bestehende sitzung beenden; für diesen
   fehlerfall ist die unabhängige konsole erforderlich.
10. mit `pbp-m` eine zweite, nach dem finalen regelwechsel neu aufgebaute
    SSH-/GUI-Verbindung herstellen. Erst wenn genau diese Verbindung mit dem
    gepinnten Host-Key funktioniert, darf die ursprüngliche SSH-Sitzung
    geschlossen werden.

scheitert die neue verbindung, wird die noch funktionierende alte sitzung
oder andernfalls die unabhängige provider-konsole zur diagnose verwendet.
dann werden IPv4-ziel, IPv4-access-adresse, SSH-port, host-key sowie jede
angehängte firewall-/security-group-/ACL-ebene geprüft. die neue einzelregel
wird nicht durch eine kurzfristige globale SSH-freigabe „repariert“. im
manuellen modus kann `pbp-m` die cloud-regel weder beweisen noch später
automatisch löschen; sie muss nach ende des zugriffs in der
provider-control-plane entfernt werden. für wiederholte nutzung ist deshalb
ein atomarer adapter mit providerseitiger TTL sicherer als die manuelle
bestätigung.

der bootstrap bricht ab, wenn eine der folgenden invarianten fehlt:

- debian 12+ oder ubuntu 24.04+ mit systemd, amd64 oder arm64;
- der von toolkit verwaltete, gesperrte und unprivilegierte GUI-benutzer
  `malwarelab`;
- eine direkte IPv4-SSH-sitzung während der VPN-einrichtung;
- mullvad `connected`, shadowsocks, port 443, auto-connect und lockdown;
- ein tatsächlich gemessener mullvad-ausgang mit `country == Germany`;
- ein eindeutiges aktives mullvad-WireGuard-interface mit globaler IPv4;
- der für `malwarelab` geladene nftables-egress-guard und der gehärtete
  downloads-mount;
- zu architektur und system-python passende, vollständig gehashte
  runtime-artefakte;
- eine gültige persona der gewählten klasse.

das sichtbare `1600x900`-display ist keine bootstrap-invariante; es wird bei
jedem browserstart geprüft und blockiert nur diesen start, falls es abweicht.

camoufox' eigener globaler downloadcache wird weder bei der installation noch
beim browserstart verwendet. auch die laufzeit-`FONTCONFIG_FILE` entsteht
deterministisch aus dem bereits SHA-256-geprüften, versionierten browserverzeichnis;
dadurch kann die python-bibliothek keine mutable browserdatei nachladen.

die browser-enterprise-policy wird beim build aus der vorhandenen
camoufox-policy und dem geprüften PBP-overlay zusammengeführt. sie erzwingt
unter anderem HTTPS-only, deaktiviert browser-DoH und browserproxy zugunsten
des kontrollierten mullvad-systemroutings, sperrt neue add-on-installationen
außer den explizit gebündelten erweiterungen, schaltet remote-debugging und
developer-UI ab, blockiert neue kamera-, mikrofon-, standort- und
benachrichtigungsfreigaben, aktiviert safe browsing und partitionierung und
verhindert sicherheitsausnahmen. dieselben sicherheitsrelevanten prefs werden
beim materialisieren und vor jedem start erneut aufgelegt; eine abweichende
policy oder persona blockiert die installation beziehungsweise den start.

vor dem erzeugen des browserprozesses setzt der launcher core-limit `0`,
`PR_SET_NO_NEW_PRIVS=1` und `PR_SET_DUMPABLE=0` und prüft diese zustände.
zusätzlich begrenzt ein systemd-geladener nftables-guard den gesamten
`malwarelab`-UID auf loopback-DNS samt zugehörigen conntrack-antworten und das
genau erkannte aktive mullvad-WireGuard-interface; alle anderen ausgänge dieses
UID werden zurückgewiesen. die sperrregel wird bereits vor der
interface-erkennung geladen, damit ein erkennungsfehler nicht offen
weiterleitet. meldet mullvad trotz fehlender browserroute `connected`, baut der
guard den tunnel einmal kontrolliert neu auf und prüft danach den normalen
browser-UID-pfad erneut; die UID bleibt währenddessen fail-closed.

`Downloads` ist ein eigener bind-mount mit `nodev,nosuid,noexec`, modus `0700`
und einem hinter einem root-only elternverzeichnis liegenden backing store.
der mount und seine inodes/optionen werden vor jedem browserstart erneut
geprüft. `noexec` verhindert nur die direkte ausführung von dort; es macht
heruntergeladene inhalte nicht vertrauenswürdig und verhindert weder das
interpretieren durch andere programme noch das kopieren an einen anderen ort.

vor jedem späteren browserstart prüft der rootgebundene policy-helper zuerst
mullvad-status, deutschland/shadowsocks 443, auto-connect, lockdown,
WireGuard-interface, UID-egress-guard und downloads-mount. danach wird der
tatsächliche deutsche mullvad-ausgang per HTTPS bestätigt. ohne beide
bestätigungen wird kein browserprozess erzeugt. nach
`PR_SET_NO_NEW_PRIVS=1` versucht der periodische sitzungsmonitor
absichtlich keinen weiteren `sudo`-aufruf: er prüft fortlaufend den
effektiven mullvad-egress direkt. der browserprozess kann die zuvor
rootgeschützte policy und den guard nicht verändern.

ein positiv falscher egress (kein mullvad, nicht deutschland oder keine
globale IPv4-adresse) schaltet den kontext sofort offline und beendet ihn. ein
vorübergehend nicht erreichbarer prüf-endpunkt schaltet den kontext zunächst
offline; die prüfung verwendet begrenztes exponentielles backoff mit jitter.
erst zwei aufeinanderfolgende erfolge schalten dieselbe verbindung wieder
online. ein relay-/IP-wechsel beendet die sitzung kontrolliert, damit die beim
start materialisierte WebRTC-adresse nicht widersprüchlich wird. es gibt
absichtlich keinen automatischen browser-neustart.

persona und browserprofil sind VM-weit und nicht releasegebunden. schema 3
bindet die persona ausdrücklich an ihre ausgewählte klasse. ein wechsel der
klasse auf derselben VM wird abgewiesen. personas der legacy-schemata 1 oder 2
können nicht auf schema 3 umgeschrieben werden, ohne den fingerprint zu
verändern; ebenso wird ein nichtleeres legacy-profil nicht migriert. in beiden
fällen ist eine frische wegwerf-VM erforderlich. PBP ersetzt weder persona
noch profil stillschweigend.

pro start entsteht ein begrenztes, rotiertes und bereinigtes JSONL-laufzeitlog
unter
`/home/malwarelab/.local/state/dynamicflow/pbp/logs/runtime-*.jsonl`.
verzeichnis und dateien haben modus `0700` beziehungsweise
`0600`. browser-`stderr` und interne tracebacks landen
ausschließlich bereinigt dort. der desktop-start zeigt bei fehlern einen
`zenity`-dialog (mit sicheren fallbacks), einer konkreten nächsten
handlung und dem logpfad.

falls ubuntu/AppArmor unprivilegierte user-namespaces einschränkt, installiert
PBP ein auf das versionierte `camoufox-bin` begrenztes
`flags=(unconfined)`-profil mit zusätzlicher `userns`-erlaubnis. die globale
user-namespace-sperre bleibt aktiv und PBP startet den browser nicht mit
`--no-sandbox`. dieses profil ist aber ausdrücklich **kein** AppArmor-
dateisystem- oder netzwerk-confinement: `flags=(unconfined)` schafft nur die
kompatibilitätsausnahme, die firefox für seine eigene sandbox benötigt. die
zusätzlichen grenzen kommen von firefox-sandbox, prozessflags, nftables,
systemd-mount und der wegwerf-VM.

## P0-ursachenanalyse und evidenzgrenze

der deterministische fehler hinter „nach dem schließen startet der
desktop-eintrag nicht mehr sichtbar“ ist im alten launcher eindeutig
nachweisbar:

1. PBP v0.1.7 registrierte `context.on("close", ...)`.
2. danach wartete der hauptthread ausschließlich in
   `threading.Event.wait(0.5)`.
3. die gepinnte synchrone playwright-laufzeit 1.61.0 stellt ereignis-callbacks
   nur zu, solange ihr dispatcher-greenlet durch einen synchronen
   playwright-aufruf gepumpt wird. `threading.Event.wait()` pumpt
   diesen dispatcher nicht.
4. das close-ereignis konnte deshalb in playwright anstehen, während der
   python-launcher weiterlief und seinen kernel-`flock` behielt.
5. der nächste start wurde korrekt als bereits laufend abgewiesen. weil der
   desktop-eintrag `Terminal=false` verwendete und keinen dialogpfad
   hatte, blieb diese fehlermeldung unsichtbar.

v0.1.8 pumpt den dispatcher alle 250 ms über ein begrenztes
`context.expect_event(...)`, klassifiziert page-close, page-crash,
unerwartetes context-close, signal und egress-abbruch getrennt und gibt den
app-lock in jedem pfad frei. native firefox-locks werden nur unter diesem
exklusiven app-lock, nach exakter prozessprüfung und nur bei nachweislich
stalen locks entfernt. übrig gebliebene prozesse werden ausschließlich über
den exakten profilparameter plus startzeitverifizierten prozessbaum mit
`TERM` und begrenztem `KILL` bereinigt.

diese analyse erklärt sicher den hängenbleibenden launcher/lock und die
unsichtbare zweite fehlermeldung. sie beweist **nicht**, warum der ursprünglich
beobachtete browser nach einigen minuten erstmals beendet wurde. ob dort ein
camoufox-/browser-crash, OOM-kill, AppArmor-denial, verlust der
XFCE/VNC-sitzung, ein signal oder eine andere VM-spezifische ursache vorlag,
kann erst auf der betroffenen echten VM anhand des neuen runtime-logs sowie
kernel-, AppArmor- und journal-ereignissen entschieden werden. ohne diese
artefakte wird keine dieser möglichkeiten als ursache behauptet.

der lokale regressionstest
`test_virtual_thirty_minute_soak_keeps_dispatching_then_closes_cleanly`
simuliert 30 minuten als 7.200 dispatcher-takte; weitere tests decken mehrere
schließen-/neustart-zyklen, lock-reacquire, egress-ausfall und relaywechsel ab.
das ist ein deterministischer code-/lifecycle-test, ausdrücklich **kein**
ersatz für den geforderten mindestens 30-minütigen soak auf einer echten VM.

## Runbook: echter VM-soak und neustarttest

`tests/pbp-vm-soak.py` ist der qualifizierende realtest. er besitzt
keinen mock-PASS-pfad. vor dem lauf muss PBP v0.1.9 auf einer ausdrücklich
disposable VM installiert sein. starte den test als `malwarelab` aus
einem terminal der laufenden VNC/XFCE-sitzung; `DISPLAY` und
`XAUTHORITY` dürfen nicht aus einer fremden SSH-sitzung erfunden werden.
kopiere nur die harness-datei auf die VM und mache sie ausführbar; übertrage
keine schlüssel oder secrets.

ein vollständiger lauf lautet:

```sh
python3 ./pbp-vm-soak.py \
  --duration-seconds 1800 \
  --normal-cycles 5 \
  --exercise-vpn-failure \
  --disposable-network-test
```

die letzten beiden optionen führen einen **echten** mullvad-disconnect mit
anschließendem reconnect aus. das kann die SSH-/VNC-verbindung unterbrechen.
verwende sie nur auf der disposable test-VM mit verfügbarer providerkonsole.
ohne diese doppelte freigabe wird die VPN-phase `SKIP` und der
gesamtlauf höchstens `BLOCKED`, niemals `PASS`.

der harness führt fünf reale WM_DELETE-schließen-/neustart-zyklen, einen
mindestens 30-minütigen wall-clock-soak, einen PID-/startzeit-geprüften
`SIGKILL` des browserprozesses, sichtbare zenity-fehlerpfade,
lock-/orphan-/persona-/logprüfungen und den echten VPN-fail-closed-test aus.
beim absichtlichen disconnect muss er den transienten offline-übergang, das
begrenzte backoff-fenster und dessen terminale erschöpfung tatsächlich
beobachten; bloßes prüfen von konstanten reicht für diesen realtest nicht.
fehlen installation, display, xdotool, zenity oder deutscher mullvad-egress,
meldet er eindeutig `BLOCKED` statt `PASS`.

das fortlaufend aktualisierte resultat liegt standardmäßig unter
`/home/malwarelab/.local/state/dynamicflow/pbp/test-results/` und
hat modus `0600`. es enthält nur status, zeitpunkte, zähler und
booleans, keine IP-adressen, persona-hashes, urls oder secrets. exitcodes:
`0` = qualifizierendes `PASS`, `1` =
`FAIL`, `2` = `BLOCKED` und `130` = unterbrochenes `BLOCKED`.

für einen kurzen verdrahtungstest ist
`--duration-seconds 60 --allow-short-nonqualifying` erlaubt; ein
solcher lauf bleibt absichtlich `BLOCKED`. falls der automatische
reconnect fehlschlägt, nutze die providerkonsole und führe
`mullvad connect --wait` aus. erst wenn der deutsche egress wieder
geprüft ist, darf ein neuer PBP-test gestartet werden.

## Fingerprint-modell und ehrliche grenze

PBP setzt nicht einzelne header oder einen handgebauten user-agent. jede der
drei klassen ist an genau ein vollständiges, im gepinnten camoufox-datensatz
vorhandenes windows-preset gebunden:

- `basic`: 4 CPU-threads, intel HD graphics 400, `1600x900`;
- `performance`: 8 CPU-threads, NVIDIA GeForce GTX 980, `1600x900`;
- `workstation`: 12 CPU-threads, intel HD graphics, `1600x900`.

der launcher verlangt, dass genau dieses klassenpreset existiert, und prüft
preset, screen, DPR, touch, WebGL und voices gegen die gespeicherte persona.
user-agent, `Win32`, OSCPU, fonts, audio-/canvas-/font-seeds, locale und
zeitzone werden gemeinsam materialisiert. das sichtbare X11-display muss
ebenfalls exakt `1600x900` haben; ein abweichendes display startet nicht.

die klasse ist fest, die zugehörigen seeds werden aber je wegwerf-VM lokal
erzeugt. PBP fragt weder eine zentrale fingerprint-datenbank noch frühere vms
oder browser-sessions ab und behauptet daher auch keine globale einzigartigkeit
oder kollisionsfreiheit. eine beim start geprüfte mullvad-IPv4 wird nur in die
laufzeitkonfiguration für WebRTC eingesetzt; schema 3 weist persona-dateien
mit gespeicherten `webrtc:*`-sessiondaten zurück. runtime-logs zeichnen nur
auf, ob eine egress-IP vorhanden und gültig war, nicht die IP oder einen
persona-hash.

eine mathematische „100 prozent unsichtbar“-garantie existiert bei
browser-fingerprinting nicht. camoufox ist selbst erkennbar, wenn eine website
genug neue oder engine-spezifische signale kombiniert. PBP verspricht deshalb
keine falsche prozentzahl. es erzwingt stattdessen prüfbare eigenschaften:
stabile persona, keine chrome/firefox-engine-lüge, keine ungewöhnlich
deaktivierten WebGL-/audio-oberflächen, deutscher mullvad-egress und
fail-closed-start.

der aktuelle lock zeigt auf den vollständigen linux-build
`150.0.2-beta.25` aus `VulpineOS/VulpineOS` tag `v0.1.8-dev.5` sowie den
python-wrapper `cloverlabs-camoufox==0.6.0`. der vendor-build prüft zusätzlich
zum SHA-256-pin den archivinhalt und verlangt `camoufox-bin` plus `libxul.so`;
binary, persona-daten und fonts dürfen nicht aus verschiedenen releases
gemischt werden. upstream-tags/commits und releases sind laut review nicht
signiert beziehungsweise nicht immutable. die aufgezeichneten hashes schützen
daher erst nach einer vertrauenswürdigen initialen prüfung der herkunft.

dieser lock bleibt unter der geforderten gecko-153-baseline und ist somit
absichtlich `blocked`. ein update muss als neuer, vollständig geprüfter PBP-
release mit provenienz-, inhalts-, smoke-, persona- und real-VM-tests erfolgen;
die bloße existenz eines neueren camoufox-tags genügt nicht.

## Reproduzierbarer privater release

`requirements.lock` pinnt alle transitiven python-abhängigkeiten samt hashes.
browser und uBlock origin sind mit exakten urls und SHA-256-werten in
`browser-assets.lock` festgelegt. vor einem update wird zunächst
`./browser-maintenance.py audit` ausgeführt und die review-policy manuell
bearbeitet. erst nach einer echten freigabe lädt der vendor-schritt die
artefakte einmal am build-system, prüft ihre hashes und erzeugt runtime-
tarballs für python 3.11, 3.12 und 3.13:

```sh
./fetch-vendor.sh amd64
./make-release.sh amd64
```

für arm64 werden dieselben befehle mit `arm64` ausgeführt. bei der derzeitigen
`blocked`-policy endet `make-release.sh` erwartungsgemäß ohne archiv. nach
einer freigabe liegt das ergebnis unter `dist/linux-ARCH/pbp.tar.gz`.
`make-release.sh` greift nicht auf das netz zu und publiziert nichts. es
kopiert den aktuellen, getesteten VPN-bootstrap als `toolkit-vpn-stage`;
dadurch enthält das archiv genau den vorgesehenen bootstrap:
`bootstrap-pbp.sh`.

ein release enthält ein internes `SHA256SUMS` über jede laufzeitdatei.
archive werden deterministisch mit epoch-mtime, numerischen root-eigentümern
und ohne links, devices oder pfadtraversal gebaut. ein äußeres
distributionsmanifest kommt erst in einem getrennten, ausschließlich vom
betreiber ausgeführten publish-schritt hinzu.

## Qualifikationsgrenze dieses quellstands

die lokalen tests prüfen parser, persona-invarianten, policy-merge,
lifecycle, egress-zustandsautomat und releaseverdrahtung. sie emulieren jedoch
keinen echten kernel, systemd-boot, nftables-datenpfad, mullvad-daemon,
AppArmor-stack oder sichtbaren camoufox-prozess. im repository liegt kein
aufgezeichnetes real-VM-`PASS` für genau diesen quellstand. er ist außerdem
bereits wegen der gecko-baseline release-blockiert.

nach einem künftig freigegebenen browser-pin muss deshalb auf jeder
unterstützten architektur mindestens der oben beschriebene 30-minuten-soak
einschließlich disconnect/reconnect ausgeführt werden. dabei sind zusätzlich
die geladenen enterprise-policies, uBlock origin, das echte `1600x900`-
display, `NoNewPrivs`/core-dump-sperre am laufenden prozess, der
UID-nftables-guard, der `nodev,nosuid,noexec`-mount sowie DNS-, WebRTC- und
IPv4/IPv6-leakverhalten von einer kontrollierten gegenstelle zu prüfen.
reboot, mullvad-relaywechsel und absichtlicher ausfall des prüf-endpunkts
müssen geschlossen statt offen fehlschlagen. erst diese evidenz qualifiziert
das systemverhalten; statische tests allein tun es nicht.

## VM-grenze

PBP ist ein privacy-/fingerprint-setup, keine malware-sandbox. für downloads
bleibt die wegwerf-VM die sicherheitsgrenze:

- keine shared folders, host-mounts oder drag-and-drop;
- VNC-clipboard ausgeschaltet lassen;
- downloads nicht automatisch öffnen;
- export nur bewusst über quarantäne/scan;
- VM nach der sitzung verwerfen.

vor dem löschen einer VM muss der mullvad-geräteplatz freigegeben werden:

```sh
sudo mullvad auto-connect set off
sudo mullvad lockdown-mode set off
sudo mullvad disconnect --wait
sudo mullvad account logout >/dev/null
sleep 10
```

das installationslog liegt root-only unter
`/var/log/toolkit-pbp-bootstrap.log`.
