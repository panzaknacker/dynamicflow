# Dynamicflow recovery-runbook

> **in development.** entfernte CLI-aktionen sind durch die unvollständige
> control-route gesperrt. die verfahren hier sind noch nicht als realer
> recovery-ablauf dieser veröffentlichung qualifiziert. aktuelle grenzen:
> [PROJECT_STATUS.md](../PROJECT_STATUS.md).

recovery bleibt fail-closed. ein verifikationsfehler wird nicht durch
`--insecure`, gelöschte locks, deaktivierten lockdown, ersetzte persona oder
ungepinntes SSH „behoben“. vor jedem eingriff zeit, instanz, gewünschte
generation, release-set, exitcode und sichere logpfade notieren; keine secrets
in den incident-kanal kopieren.

## Erste einordnung

auf dem operator:

```sh
flow doctor
flow serving show
flow instance status NAME
flow instance logs NAME
```

wenn SSH bereits vertrauenswürdig gepinnt und der direktzugriff bewusst nötig
ist:

```sh
flow instance exec NAME -- sudo flow instance-runtime status
```

`instance-runtime status` liest nur den verifizierten lokalen state und macht
keinen netzwerkrequest. ist SSH nicht erreichbar oder der hostkey unklar,
providerkonsole verwenden; nicht auf passwort-/root-SSH zurückfallen.

wichtige zielpfade:

```text
/var/lib/dynamicflow/instance/runtime-config.json
/var/lib/dynamicflow/instance/apply/apply.json
/var/lib/dynamicflow/instance/apply/checkpoint.json
/var/lib/dynamicflow/instance/apply/logs/<phase>.log
/var/lib/dynamicflow/instance/apply/artifacts/
```

diese dateien sind root-only und inhaltlich gebunden. nicht bearbeiten oder
löschen. logs vor weitergabe auf secrets und öffentliche ips prüfen.

## Serving ist nicht erreichbar oder unhealthy

auf der serving-konsole mit dem provisionierten home:

```sh
sudo flow --home /var/lib/dynamicflow-serving-operator status serving
sudo flow --home /var/lib/dynamicflow-serving-operator logs serving --lines 500
sudo systemctl status dynamicflow-serving.service --no-pager
```

danach denselben gewünschten zustand erst planen, dann erneut abgleichen:

```sh
sudo flow --home /var/lib/dynamicflow-serving-operator \
  start serving --plan --public-url https://serving.example:8443 \
  --release-public-key /var/lib/dynamicflow-serving/trust/release.public.pem \
  --desired-public-key /var/lib/dynamicflow-serving/trust/desired-state.public.pem \
  --control-public-key /var/lib/dynamicflow-serving/trust/control.public.pem
sudo flow --home /var/lib/dynamicflow-serving-operator \
  start serving --public-url https://serving.example:8443 \
  --release-public-key /var/lib/dynamicflow-serving/trust/release.public.pem \
  --desired-public-key /var/lib/dynamicflow-serving/trust/desired-state.public.pem \
  --control-public-key /var/lib/dynamicflow-serving/trust/control.public.pem
```

die expliziten trust-pfade sind für eine einmalige reparatur oder das bewusste
umbinden der gespeicherten quellen gedacht. eine gültige schema-2-referenz
enthält state-/release-root, endpoint, dienstbenutzer und alle drei
public-key-quellen; im normalfall genügen daher `start serving --plan` und
`start serving`. `status` migriert oder überschreibt die referenz nie. eine
gültige schema-1-referenz wird erst beim nächsten erfolgreichen reconcile
atomar auf schema 2 geschrieben.

ein vorhandenes vollständiges TLS-paar wird erhalten. fehlt genau eine hälfte
oder passt das paar nicht, bricht `flow` ab. nicht die verbleibende hälfte
löschen; zertifikat und key aus sicherem backup als paar restaurieren oder eine
bewusste trust-rotation planen.

während des ausfalls bleiben bereits installierte profile und der lokale
checkpoint aktiv. es gibt keinen unsignierten fallback. nach wiederkehr startet
der persistente fünf-minuten-timer den festen reconcile automatisch; diese
eigenschaft bleibt bis zum echten VM-ausfalltest ein release-gate. prüfen sie
zunächst timer, journal und neuen status:

```sh
flow instance exec NAME -- sudo systemctl status \
  dynamicflow-instance-reconcile.timer --no-pager
flow instance exec NAME -- sudo journalctl -b \
  -u dynamicflow-instance-reconcile.service --no-pager
flow instance status NAME
```

nur wenn der timer nicht zeitnah reconciliiert und die ursache verstanden ist,
den identischen festen one-shot bewusst einmal ausführen:

```sh
flow instance exec NAME -- sudo flow instance-runtime reconcile
```

exitcode 8 nach vollständig verifiziertem apply bedeutet einen partiellen
status-/log-upload, nicht automatisch einen zurückzurollenden profilzustand.
der checkpoint bleibt fail-closed angewendet; der nächste timerlauf versucht
den bericht erneut. vor manueller wiederholung deshalb lokalen runtime-status
und unit-journal gegen die gemeldete desired-generation vergleichen.

bei einer revocation gilt dasselbe strenger: `reporting_partial` bedeutet,
dass lokale SSH-sperre und fail-closed zustand bereits aktiv sind, aber der
signierte `state=revoked`-ack oder das finite `phase_fail_closed/revoked`-event
nicht vollständig ankamen. VM isoliert lassen und den timer retryen lassen;
keinen installer und keine SSH-ausnahme für den ack starten.

## Enrollment-antwort ging verloren

wenn serving das secret möglicherweise schon konsumiert hat, **keinen neuen
instanznamen, keine neue identity und keinen neuen code improvisieren**. auf
derselben VM denselben bootstrap beziehungsweise denselben
`instance-runtime enroll`-aufruf mit identischen öffentlichen trust-optionen
wiederholen. die runtime erhält ihre bestehende instance identity und versucht,
den gebundenen signierten desired state abzurufen.

exitcode `8` beziehungsweise `enrollment_outcome_unknown` bedeutet, dass die
recovery noch nicht abgeschlossen ist. serving-verfügbarkeit reparieren und
denselben lauf wiederholen. erst ein verifizierter lokaler state oder eine
bewusste revocation beendet den zwischenzustand.

## Enrollment-code ist abgelaufen oder möglicherweise gestohlen

- code und secret nicht erneut anzeigen, speichern oder versenden.
- ziel-VM bis zur klärung über providerkonsole identifizieren; falsche
  instance-/profilwerte nicht ausprobieren.
- mit `flow enroll list` zustand und ablaufzeit prüfen.
- ist bereits eine instance identity konsumiert, sofort
  `flow instance revoke NAME` veröffentlichen und die VM providerseitig
  isolieren, bis der zielstatus die revocation bestätigt.
- einen noch nicht konsumierten code mit
  `flow enroll revoke --id ENROLLMENT_ID` oder eindeutig nach instanznamen mit
  `flow enroll revoke --name NAME` serverseitig widerrufen. der befehl ist
  control-signiert, auditiert und setzt einen exakt passenden lokalen
  `issued`-datensatz erst nach bestätigter remote-revocation wieder auf
  `draft`. lokale dateilöschung allein widerruft keinen code. ist der code
  bereits konsumiert, verweigert dieser pfad bewusst und verlangt den
  signierten `flow instance revoke NAME`-ablauf.

nach ablauf einen neuen instanznamen verwenden, wenn nicht eindeutig bewiesen
ist, dass der alte code nie konsumiert wurde.

## Apply wurde unterbrochen oder meldet `apply_busy`

der äußere target-apply-lock und der reconcile-lock sind kernel-`flock`s. die
lockdatei allein beweist keinen aktiven prozess und darf nicht gelöscht werden.

auf providerkonsole oder über explizites, gepinntes exec:

```sh
flow instance exec NAME -- sudo flow instance-runtime status
flow instance exec NAME -- sudo ps -eo pid,ppid,lstart,user,args
```

keine instanz-/enrollment-secrets sollten in den argumenten stehen. ist kein
aktiver apply mehr vorhanden, denselben verifizierten plan fortsetzen:

```sh
flow instance exec NAME -- sudo flow instance-runtime reconcile
```

vollständige phasen werden übersprungen; die erste nicht vollständige phase
startet mit neuem preflight. ein neuer plan kann ein unvollständiges journal
nicht ersetzen. zuerst den bestehenden plan sicher abschließen oder anhand
seines fail-closed-zustands bewusst neu aufsetzen.

## Release- oder desired-state-verifikation schlägt fehl

sofort stoppen. nicht `current` umbiegen, keine manifestdatei editieren und
keinen public key aus der fehlerhaften antwort übernehmen.

operatorseitig:

```sh
flow release verify
flow serving show
flow doctor
```

prüfen:

- stimmen release-/desired-/control-key-ID mit dem ursprünglich gesicherten
  operator-state überein;
- ist die desired-generation monoton und an dieselbe instanz/dasselbe profil
  gebunden;
- liegt ein höheres release mit falschen bytes oder ein echter key-incident
  vor.

bei einem fehlerhaften, aber gültig signierten release ein korrigiertes set mit
höherer generation bauen, verifizieren und atomar veröffentlichen. ein
downgrade auf eine niedrigere generation wird absichtlich abgelehnt.

bei `version_conflict` niemals alte sets, `<release-root>/history/` oder
`<FLOW_HOME>/releases/manifest-history/` löschen. der fehler belegt, dass eine
bereits verwendete `{Komponente, Version, Target}`-koordinate andere bytes,
eine andere größe oder einen anderen artefaktnamen erhalten sollte. ursache
prüfen, die betroffene komponentenversion erhöhen, reproduzierbar neu bauen und
den read-only publish-plan wiederholen. ein bereits widersprüchlicher
altbestand bleibt fail-closed und benötigt eine explizite, signierte
trust-domain-migration; lexikographisch „einen gewinner“ auszuwählen ist kein
recovery-verfahren.

auch `<FLOW_HOME>/releases/manifest-history.index.json`, `staged.json` und
`signed-manifest.json` nie einzeln löschen oder aus verschiedenen backups
mischen. der index bindet die vollständige private set-liste und höchste
generation. `version_policy` mit `deletion detected` bedeutet: build, verify
und publish bleiben absichtlich gesperrt, bis history und index gemeinsam aus
dem verschlüsselten operator-backup restauriert sind. eine stage/export-
abweichung ist ein unterbrochener operator-commit; `flow release build` mit
intakten quellen und einer generation oberhalb der history stellt einen neuen,
konsistenten commit her.

ein vorhandenes stage oder ein nichtleeres history-verzeichnis ohne index wird
nicht implizit migriert. auch wenn einzelne signierte einträge noch gültig
aussehen, kann der rest ausgedünnt sein. normalen build nicht erzwingen;
vollständigen zusammengehörigen zustand restaurieren oder eine ausdrücklich
auditierte trust-domain-migration planen.

fehlen nach einem lokalen crash nur history oder `current`, das immutable set
ist aber vollständig vorhanden, zuerst `flow release publish --plan` prüfen.
`resume_committed_set=true` erlaubt danach denselben lokalen publish auch wenn
die flüchtigen quellpfade nicht mehr existieren. bei unsicheren owner-/modi,
abweichenden digests oder einem fehlenden set wird dieser recovery-pfad
abgelehnt. remote stets dasselbe vollständige, verifizierte bundle erneut
senden; keinen pointer von hand ändern.

bei verlust oder kompromittierung eines signing-private-keys vorhandenen state
nicht überschreiben. aus verschlüsseltem offline-backup restaurieren oder eine
neue trust-domain mit neu-provisionierung und neu-enrollment planen. serving
besitzt keine rettende kopie. ein einzelner austausch von
`release.public.pem` reicht nicht: alte manifest-tombstones müssen weiterhin
unter einer versioniert unterstützten alten wurzel verifizierbar sein. bis ein
multi-key-migrationsverfahren implementiert und getestet ist, ist
neu-provisionierung die sichere grenze.

## SSH-apply ist fehlgeschlagen

ein fehler nach SSH-aktivierung deaktiviert `ssh.service` und `ssh.socket`,
wenn die gewünschte policy nicht unabhängig bestätigt werden kann. das ist
der sichere zustand.

providerkonsole verwenden und prüfen:

```sh
sudo flow instance-runtime status
sudo sed -n '1,240p' /var/lib/dynamicflow/instance/apply/logs/ssh.log
sudo sshd -T
sudo systemctl status ssh.service ssh.socket --no-pager
```

das log ist begrenzt und redigiert, bleibt aber sensibel. ursache wie
unsicherer admin-home, fremde `Match`-blöcke, fehlender OpenSSH-server oder
abweichende `authorized_keys` korrigieren. dann denselben reconcile über die
konsole erneut ausführen. passwortauthentisierung oder root-login nicht als
temporären workaround aktivieren.

## SSH-hostkey hat sich geändert

`flow instance status` beziehungsweise jeder spätere SSH-aufbau stoppt bei
einem anderen gepinnten key. mögliche ursachen sind MITM, falsche VM,
neuinstallation oder legitime hostkey-rotation.

1. nicht verbinden und `ssh-keyscan` nicht verwenden.
2. ziel-IP, provider-instanz-ID und Ed25519-fingerprint in der
   providerkonsole vergleichen.
3. nur bei bewusst autorisierter rotation die einzelne öffentliche datei
   `/etc/ssh/ssh_host_ed25519_key.pub` über den authentisierten konsolenkanal
   zum operator übertragen.
4. lokal prüfen, dass es eine kleine reguläre nicht-symlink-datei ist.
5. rotation explizit auditieren:

```sh
flow instance hostkey rotate NAME \
  --public-key-file /ABS/PATH/ssh_host_ed25519_key.pub
flow instance list
flow instance ssh NAME
```

der rotationsbefehl macht selbst keine netzwerkverbindung. er zeigt alten und
neuen fingerprint. bei nicht erklärbarer änderung instanz isolieren und aus
sauberem image neu enrollen.

fehlt dagegen nur der **erste** lokale pin, ist `rotate` falsch. nach
authentisiertem konsolenexport und gebundenem endpunkt einmalig ausführen:

```sh
flow instance hostkey pin NAME \
  --public-key-file /ABS/PATH/ssh_host_ed25519_key.pub
```

ein serving-status oder `ssh-keyscan` darf diesen initialen trust nicht
ersetzen. anschließend `flow instance status NAME` zum vergleich aufrufen.

## Lokaler SSH-private-key fehlt oder wurde gestohlen

serving und ziel-VM besitzen keine kopie. die key-metadaten nicht auf einen
erfundenen private key umbiegen.

- bei verlust: offline-backup restaurieren. ist kein backup vorhanden, über
  providerkonsole einen neuen kontrollierten enrollment-/desired-state-pfad
  aufbauen oder die disposable VM neu erstellen.
- bei diebstahl: instanz isolieren, `flow instance revoke NAME` veröffentlichen
  und erst nach remote-bestätigung einen ersatz aufbauen.
- bei noch vorhandenem alten key die normale zweistufige rotation aus dem
  operator-runbook verwenden.

## Neue target-`flow`-binary startet nach dem handoff nicht

ein binarywechsel gilt erst nach dem folgenden vollständigen timerlauf als
angewandt. die alte invocation schreibt beim handoff keinen profil-checkpoint.
kann `/usr/local/bin/flow` danach nicht starten, gibt es absichtlich keinen
automatischen downgrade: zuerst den fehlerhaften release-satz sperren
beziehungsweise einen korrigierten satz mit **höherer** generation signieren
und dem desired state zuweisen. sonst würde ein restaurierter alter runner
denselben defekten satz erneut aktivieren.

danach ausschließlich über die authentisierte providerkonsole:

```sh
sudo systemctl stop dynamicflow-instance-reconcile.timer
sudo systemctl stop dynamicflow-instance-reconcile.service || true
sudo find /var/lib/dynamicflow/instance/apply/runtime-recovery \
  -xdev -maxdepth 1 -type f -user root -links 1 -perm 0700 \
  -name '*.flow' -printf '%f %s bytes\n'
```

jeder zulässige dateiname ist `<64-kleinbuchstabige-hex-Zeichen>.flow`.
wählen sie ausschließlich den digest der vorher akzeptierten, bekannten
release-binary aus dem operator-releaseverlauf. bei der initialen version ist
dies der `flow`-digest des bootstrap-release-satzes. prüfen sie vor dem
kopieren, dass `sha256sum` exakt denselben digest wie der dateiname liefert;
keine datei allein aufgrund ihres alters auswählen.

```sh
candidate=/var/lib/dynamicflow/instance/apply/runtime-recovery/EXAKTER_SHA256.flow
sudo stat -c '%F %U:%G %a %h %s' "$candidate"
sudo sha256sum "$candidate"
sudo install -o root -g root -m 0755 \
  "$candidate" /usr/local/bin/.flow-recover
sudo mv -T /usr/local/bin/.flow-recover /usr/local/bin/flow
sudo sync
sudo /usr/local/bin/flow --version
```

erst wenn serving den korrigierten höheren satz und desired state ausliefert:

```sh
sudo systemctl enable --now dynamicflow-instance-reconcile.timer
sudo systemctl start dynamicflow-instance-reconcile.service
sudo /usr/local/bin/flow --json instance-runtime status
```

die recovery-dateien bleiben als audit-/notfallmaterial erhalten. nicht
pauschal löschen und keinen älteren release-satz als normalen rollback
veröffentlichen; die monotone generation schützt absichtlich vor downgrades.

## VPN-/mullvad-phase ist fehlgeschlagen

der sichere rollback ist auto-connect aus, lockdown **an**, tunnel getrennt.
dadurch kann SSH/VNC unterbrochen sein. providerkonsole verwenden:

```sh
sudo mullvad status --json
sudo mullvad lockdown-mode get
sudo journalctl -b -u mullvad-daemon.service --no-pager
```

statusausgaben können relay/IP-metadaten enthalten; nicht ungefiltert in
tickets kopieren. accountnummer niemals in argv oder log schreiben.

nach behebung bewusst verbinden und den deutschen egress prüfen, ohne die
gemeldete IP zu persistieren:

```sh
sudo mullvad connect --wait
curl -4 --fail --silent --show-error --proto '=https' --tlsv1.2 \
  https://am.i.mullvad.net/json
sudo flow instance-runtime reconcile
```

für PBP müssen `mullvad_exit_ip=true`, `country=Germany`, shadowsocks port 443,
auto-connect und lockdown gelten. ein bloßes „connected“ reicht nicht. den
lockdown nur zur endgültigen decommission abschalten.

## PBP schließt oder startet nicht sichtbar

der desktoplauncher zeigt ab PBP v0.1.8 einen dialog/notification und einen
sicheren runtime-logpfad. kein systemd-auto-restart hinzufügen.
`flow instance logs NAME --component pbp` enthält nach dem nächsten
fünf-minuten-reconcile ausschließlich finite lifecycle-codes; fehlende
remote-ereignisse beweisen daher weder, dass kein crash auftrat, noch ersetzen
sie die lokalen runtime-/journal-/coredump-belege.

in der aktiven XFCE/VNC-sitzung zuerst den sichtbaren fehler notieren. danach
über explizites exec oder providerkonsole folgende evidenz erfassen:

```sh
flow instance logs NAME --component pbp
flow instance exec NAME -- sudo find \
  /home/malwarelab/.local/state/dynamicflow/pbp/logs \
  -maxdepth 1 -type f -name 'runtime-*.jsonl' -printf '%TY-%Tm-%TdT%TH:%TM:%TS %m %u %p\n'
flow instance exec NAME -- sudo ps -eo pid,ppid,lstart,user,args
flow instance exec NAME -- sudo journalctl -b -u tigervncserver@:1.service --no-pager
flow instance exec NAME -- sudo journalctl -b -k --no-pager
flow instance exec NAME -- sudo coredumpctl list --no-pager
flow instance exec NAME -- sudo ausearch -m AVC,USER_AVC -ts boot
```

`ausearch` oder `coredumpctl` kann auf der distribution fehlen; dies als
`not available` dokumentieren, nicht als „keine denials/crashes“.

relevante pfade:

```text
/home/malwarelab/.local/share/toolkit-pbp/browser.lock
/home/malwarelab/.local/share/toolkit-pbp/profile
/etc/toolkit/pbp-persona.json
/home/malwarelab/.local/state/dynamicflow/pbp/logs/runtime-*.jsonl
/var/log/toolkit-pbp-bootstrap.log
```

`browser.lock`, `.parentlock`, `parent.lock` oder `lock` niemals blind löschen.
der launcher entfernt nur nachweislich stale native locks unter seinem eigenen
app-lock und nach exakter profilprozessprüfung. einen normalen desktop-start
erneut versuchen; ein unklarer besitzer bleibt bewusst blockiert.

persona-datei und browserprofil nicht löschen oder getrennt restaurieren. bei
`persona changed` die VM aus einem zusammengehörigen snapshot von persona,
profil und dynamicflow-checkpoint wiederherstellen oder neu aufsetzen.

die bekannte v0.1.7-lockursache und die noch offene ursache des ursprünglichen
ersten browserendes stehen in [PBP-INCIDENT.md](PBP-INCIDENT.md).

## PBP beendet wegen egress- oder check-ausfall

- falscher/nichtdeutscher egress: sofortiger fail-closed-abbruch ist korrekt.
- temporär unerreichbarer check: kontext bleibt offline, begrenzter backoff;
  erst zwei erfolge geben frei.
- ausgeschöpfter backoff oder relay-/IP-wechsel: kontrolliertes ende ist
  korrekt, weil die materialisierte WebRTC-IP sonst widersprüchlich wäre.

mullvad und endpoint reparieren, deutschen egress bestätigen und PBP danach
bewusst neu aus dem desktop starten. kein automatisches restart-loop.

## VNC ist nicht erreichbar oder rotation scheitert

```sh
flow instance exec NAME -- sudo systemctl status tigervncserver@:1.service --no-pager
flow instance exec NAME -- sudo ss -H -ltn 'sport = :5901'
```

zulässig sind ausschließlich `127.0.0.1:5901` und optional `[::1]:5901`;
mindestens IPv4-loopback muss vorhanden sein. jeder wildcard-/public-listener
ist ein incident: dienst stoppen und nicht die firewallausnahme erweitern.

`flow instance secret rotate NAME --secret vnc` restauriert bei fehlgeschlagenem
restart, aktivem `PasswordFile`, vncauth- oder listenercheck die zuvor
descriptor-relativ verifizierten bytes von root-secret und beiden runtime-
passwortdateien. der feste one-shot folgt keinen symlinks und akzeptiert keine
pfade. wenn pfade währenddessen getauscht wurden oder auch die restaurierung
nicht sicher geprüft werden kann, bleibt die feste VNC-unit gestoppt;
providerkonsole verwenden und die root-only logs prüfen. das alte oder neue
passwort nicht in diagnoseausgaben schreiben.

## Reboot-/resume-probleme

nach reboot zunächst lokal:

```sh
sudo flow instance-runtime status
sudo systemctl status dynamicflow-instance-reconcile.timer --no-pager
sudo journalctl -b -u dynamicflow-instance-reconcile.service --no-pager
sudo systemctl is-active ssh.service
sudo systemctl is-active tigervncserver@:1.service
sudo mullvad status --json
```

dann vom operator `flow instance status NAME` prüfen. der automatische
reconcile ist implementiert, aber bis zum dokumentierten vier-VM-test noch
keine freigegebene verfügbarkeitseigenschaft. falls trotz aktivem timer keine
aktuelle generation gemeldet wird, unit-journal und serving-erreichbarkeit
untersuchen; erst danach bewusst `sudo flow instance-runtime reconcile`
ausführen und den resultierenden status/log sichern.

## Wann neu aufsetzen

neuaufsetzen statt lokaler reparatur ist erforderlich, wenn mindestens eines
gilt:

- root-kompromittierung oder unerklärter SSH-hostkey-wechsel;
- verlorene/inkonsistente PBP-persona ohne zusammengehöriges backup;
- manipuliertes runtime-state/journals oder unsichere symlink-/owner-struktur;
- signing-key-incident ohne vertrauenswürdigen restore;
- fail-closed-zustand kann unabhängig nicht bestätigt werden.

nur ausdrücklich disposable vms löschen oder neu installieren. vorher mullvad-
geräteplatz über die providerkonsole freigeben, soweit dies sicher möglich ist.
