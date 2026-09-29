# Dynamicflow-Bedrohungsmodell

Stand: 21.09.2026. Dieses Modell trennt ausführbare lokale Funktionen von
Komponentenverhalten und der noch gesperrten Zielarchitektur. Es ist keine
Produktionsfreigabe; die realen VM-Gates stehen im
[Lab-/E2E-Runbook](LAB-E2E-RUNBOOK.md).

## Was dieser Snapshot tatsächlich freigibt

| Ebene | Aktueller Stand | Nachweis / Grenze |
| --- | --- | --- |
| Lokaler Go-Kern | Profile, lokale Schlüssel-/Trust-Verwaltung, Release-Prüfung und expliziter lokaler Publish-Pfad sind vorhanden. | `make check` prüft Build, Unit-/Race-Tests, vet und Sicherheitsverträge; [Prüfprotokolle](VERIFICATION.md). |
| Operator-Remote-Aktionen | Enrollment, Serving-Lifecycle, Instanz-SSH/GUI/Exec/Apply/Revoke, Remote-Publish und ausführender Lab-Lauf sind gesperrt. | `control_route_unavailable` tritt vor State-Zugriff, Netzwerk oder Kindprozess auf; [Gate-Regression](../internal/cli/control_route_gate_test.go). |
| Komponenten und Roh-Runtimes | Serving-, Instanz- und Installer-Code ist teilweise vorhanden und separat testbar. | Das Vorhandensein eines Raw-Entrypoints ist keine freigegebene Operator-Route und kein Ersatz für deren Gate. |
| Gesamte Plattform | Verifizierter Transport über Control und vollständiger Release mit allen Komponenten fehlen. | Keine Vier-VM-Abnahme, kein Reboot-/Soak-Nachweis; [Entwicklungsstand](DEVELOPMENT.md). |

Die folgenden Tabellen modellieren auch das beabsichtigte Zusammenspiel.
Insbesondere Aussagen über geroutetes SSH, Remote-Publish, Enrollment und
Widerrufsbestätigungen sind Sicherheitsanforderungen an die Zielarchitektur,
keine heute durchgehend ausführbaren Workflows. Lokale Komponenten-Tests
belegen nur ihren jeweiligen Umfang. Gates werden nicht durch direkte
Roh-Runtime-Aufrufe umgangen.

## Schutzgüter

- Release-, Desired-State- und Control-Private-Keys auf dem Operator-Rechner;
- private SSH-Keys je Instanz und gepinnte SSH-Hostkeys;
- private Instance Identity auf jeder Ziel-VM;
- signierte Release-Sets und Desired-State-Generationen;
- einmalige Enrollment-Secrets;
- Mullvad-Account, VNC-Passwort und PBP-Browserprofil;
- die VM-weit stabile PBP-Persona;
- Audit-, Status- und technische Logs, soweit sie Metadaten offenlegen.

## Vertrauensgrenzen der Zielarchitektur

Der Operator-Rechner ist die Autorisierungswurzel. `control` ist ein
gehärteter Transport- und Policy-Hop, aber weder Signing-Autorität noch
Private-Key-Tresor. `serving` ist HTTPS-Transport und Zustandskoordinator, aber
weder Signing-Autorität noch allgemeiner Root-Command-Server. Eine `instance`
vertraut nur einem explizit gepinnten TLS-Zertifikat sowie getrennten Release-
und Desired-State-Public-Keys. Instances initiieren HTTPS; Serving initiiert
niemals SSH.

Nur beim Bootstrap des ersten Control-Knotens existiert ein direkter,
unabhängig hostkey-verifizierter SSH-Pfad vom Operator. Danach kontaktiert die
Operatorseite ausschließlich gepinnte Control-Knoten. Serving und Instanzen
werden administrativ über eine gebundene Control-Route erreicht; die
Zielauthentisierung bleibt dabei Ende-zu-Ende, und private Zielschlüssel
bleiben lokal. Mullvad und `https://am.i.mullvad.net/json` sind externe
Routing- und Verfügbarkeitsabhängigkeiten. Providerkonsole, Cloud-Firewall,
DNS, Hypervisor, physischer Host und der Operator-Account liegen außerhalb von
dynamicflow und müssen separat geschützt werden.

Angenommen wird:

- Der Operator-Rechner ist zum Signierzeitpunkt vertrauenswürdig;
- die beim gehärteten Bootstrap unabhängig übertragenen Pins/Digests sind
  authentisch;
- die Providerkonsole authentisiert die richtige VM;
- Kernel und root der Ziel-VM sind vor dem Enrollment nicht bereits
  kompromittiert.

## Bedrohungen, Komponentenkontrollen und verbleibende Wirkung

| Bedrohung | Kontrollen | Verbleibende Wirkung / sichere Reaktion |
| --- | --- | --- |
| Kompromittiertes Control | Keine Release-, Desired-State- oder langfristigen Ziel-SSH-Private-Keys auf Control; Ende-zu-Ende-Zielauthentisierung; gebundene Ziel- und Control-Hostkeys; feste erlaubte Forwarding-Policy; auditierte Route. | Ein Angreifer kann Verfügbarkeit und Metadaten beeinflussen, Verkehr blockieren und interaktive Sitzungen beobachten. Er darf ohne lokalen Zielschlüssel und passenden Ziel-Pin keine andere Instanz authentisieren. Control gilt bis zu Ersatz/Rotation als kompromittiert; kein direkter Operator-Fallback. |
| Verwechslung der Control-Route oder unsicherer Failover | Die Route bindet System, Aktion, Ziel, Control-ID, Control-Hostkey und Ziel-Hostkey; nur verifizierte aktive Mesh-Mitglieder; keine DNS-/Hostkey-Downgrades. | Ohne eindeutig sichere Route stoppt die Operation als `route_unavailable`. Verfügbarkeit wird der Vertrauensprüfung untergeordnet. |
| Mesh-Split-Brain oder manipulierte Mitgliedschaft | Signierte, generationsgebundene Mitgliedschaft; zweiphasiger Beitritt/Austritt; monotone lokale High-Water; widersprüchliche Generationen werden abgelehnt. | Keine automatische Mehrheitsannahme aus bloßer Erreichbarkeit. Der Operator muss die Membership über einen unabhängigen vertrauenswürdigen Pfad reparieren. |
| Kompromittiertes Serving | Keine Signing- oder SSH-Private-Keys auf Serving; die Instanz prüft Release und Desired State unabhängig; content-addressed Sets; lokale Operator- und Instanz-High-Water; signierte Manifest-Tombstones; kein Command-Endpunkt. | Ein Angreifer kann ausfallen lassen, Requests beobachten, Enrollment verbrauchen/verhindern, alte bereits autorisierte Daten anbieten, Status/Logs manipulieren oder `sets/` **und** `history/` löschen. Signaturen verhindern neue Root-Inhalte; monotone lokale Checkpoints erkennen Replay für bekannte Operatoren/Instanzen. Eine vollständig gelöschte Serving-Historie ist nicht selbst authentisiert und muss über Operator-Checkpoint/Backup als Incident erkannt werden. |
| Gestohlener Enrollment-Code | 256-Bit-Secret, reine Digest-Speicherung, kurze TTL, konstante Secret-Prüfung, Bindung an Instanz und Profil, atomarer One-shot-Konsum. | Vor dem Konsum kann der Dieb die gebundene Identität übernehmen oder den legitimen Betreiber aussperren. Kein Code darf in Chat, URL, argv, History oder Log. Ein Verdacht bedeutet: nicht weiterverwenden und bis Revocation/Expiry keiner Instanz vertrauen. |
| Enrollment-Replay | Konsum und Instance-Public-Key werden unter exklusivem Lock atomar geschrieben; ein zweiter oder paralleler Konsum scheitert. Spätere Requests haben Timestamp und One-use-Nonce. | Eine verlorene HTTP-Antwort kann einen unbekannten Ausgang erzeugen; derselbe Runtime-Lauf versucht die Recovery mit derselben stabilen Instance Identity statt einer neuen Identität. |
| Falsche Instanz oder falsches Profil | Enrollment, Desired State und Antwort wiederholen Instanz/Profil; die Signatur bindet Generation, Release-Set und SSH-Keys; der lokale Built-in-Graph wird mit dem signierten Graphen verglichen. | Jede Abweichung stoppt vor dem Apply. Es gibt keinen „Best-Effort“-Profilwechsel. |
| Gestohlener lokaler SSH-Key | Standardmäßig eigener Ed25519-Key je Instanz, Dateien `0600`, `IdentitiesOnly`, keine Übertragung; überlappende Rotation, danach Entfernung; lokale Revocation. | Ein Angreifer kann bis zur entfernten Key-Generation wie der Operator zugreifen. Serving kann einen verlorenen Private Key nicht wiederherstellen. Restore aus sicherem Backup, Rotation oder Neuaufsetzen ist nötig. |
| Verzögerte Revocation-Bestätigung | Ein signierter Desired State entfernt SSH-Keys; der feste Target-One-shot sperrt lokal ohne Installer/SSH und meldet `revoked=true`, `fail_closed=true` sowie ein finites kritisches Ereignis über ausgehendes HTTPS. | Bei einem Reporting-Ausfall bleibt die Sperre aktiv, und Exitcode 8 wird durch den Timer erneut gemeldet. Bis zum signierten Ack oder zur Provider-Isolation gilt die Zielseite nicht als bereinigt. |
| Gestohlener Release-/Desired-Key | Getrennte Schlüssel und lokale Auditspur; Serving besitzt nur Public Keys. | Der Release-Key erlaubt signierten Root-Code, der Desired-Key dessen Zielzuweisung; eine Kompromittierung ist ein Root-of-Trust-Incident. Die aufbewahrte Manifest-Historie ist an den bisherigen Release-Public-Key gebunden. Eine Rotation der Vertrauenswurzel braucht ein versioniertes Multi-Key-Migrationsverfahren oder eine bewusste Neu-Provisionierungs-/Neu-Enrollment-Zeremonie; ein einzelner still ersetzter Key wird fail-closed abgewiesen. |
| Gestohlener Serving-Admin-Key (historisch `control` genannt) | Signierte, body-/pfad-/methoden-/noncegebundene Requests; der Serving-Admin-Key kann keine Release- oder Desired-Signatur erzeugen. | Status/Logs und Enrollment-Verwaltung sind betroffen; ohne Desired-Key kann kein neuer Inhalt autorisiert werden. Admin-Trust muss bewusst ersetzt werden. Der Schlüssel ist keine Control-Knotenidentität. |
| Manipuliertes Release, Versions-Rebinding oder Verlust des Operator-Katalogs | Ed25519 über kanonisches Manifest; direkte Digest-/Größen-/Target-/Pfadbindung; eine Version je Komponente über alle Targets; kein `any` plus exaktes Target; harte Manifest-/Bundle-Grenzen; descriptor-relative Owner-/Single-Link-E/A bis zu allen Set-Ancestors; Private-Key-Scan auch in tar.gz; atomare Aktivierung; Revocations. Vor dem Signieren sowie bei Verify/Publish prüft der Operator die gesamte private Manifest-Historie, deren nur für den Owner lesbaren Setlisten-/Generations-Checkpoint und den Stage-/Export-Commit. Vor Plan und Publish prüft Serving alle Sets und signierten Tombstones. | Manipulation, Teilverlust des Katalogs, Generations-Rollback oder `{Komponente,Version,Target}` mit anderem Namen/Digest/Größe führt zu Exitcode 5 und keiner neuen Signatur/Aktivierung. Der vorherige vollständige Satz bleibt aktiv. Ein beschädigtes oder historisch widersprüchliches Set blockiert weitere Veröffentlichung fail-closed und wird nicht durch zufälliges partielles Backfill „repariert“. Die Komponentenversion muss erhöht oder der Incident auditiert migriert werden. Das gemeinsame Zurückrollen oder Löschen von privater History **und** Checkpoint durch einen Angreifer mit Dateizugriff auf den Operator bleibt ein Root-of-Trust-Incident und benötigt ein externes verschlüsseltes Backup. |
| Parallele Operator-Release-Operationen | Build, Verify, Publish und Publish-Plan halten denselben nicht blockierenden Operator-Lock über jeden Zugriff auf Stage und Artefakte, beim Remote-Publish bis nach Streaming und Aktivierungsbeweis. Der Lock ist nur für den Owner lesbar, exakt `0600`, Single-Link, mit `O_NOFOLLOW` geöffnet und durch Pfad-/FD-Identität gebunden. | Genau eine Operation gewinnt; jede weitere endet sofort mit `release_busy`/Exitcode 6 und verändert Stage sowie Artefakte nicht. Ein unsicherer oder manipulierter Lock führt zu `release_lock` statt zu ungeschütztem Fortsetzen. |
| Abbruch oder defektes Binary beim Target-Self-Upgrade | Exakt architekturgebundene erste `flow`-Phase; neues und bisher laufendes Binary werden content-addressed, root-only, Single-Link und mit fsync persistiert; `/usr/local/bin/flow` wird FD-relativ atomar ersetzt; der alte Prozess stoppt vor Profilphasen und Checkpoint. | Vor dem Rename läuft das alte Binary weiter; danach startet nur der nächste Timer das neue. Ein korrekt signiertes, aber logisch nicht startbares Binary benötigt Providerkonsolen-Recovery aus dem bekannten vorherigen Digest und einen korrigierten höheren Release-Satz; kein automatischer Downgrade. |
| Manipulierter Desired State | Separate Signatur; Instanz-, Profil-, Release-, Ablauf- und Generationsbindung; gleiche Generation mit anderen Bytes und Rückschritte werden abgelehnt. | Serving kann einen gültigen Zustand zurückhalten, aber keinen neuen erzeugen. |
| MITM beim ersten Bootstrap | Der Quickstart dokumentiert die TLS-Grenze; danach CA, Leaf-Pin und Signing-Public-Keys; der gehärtete Weg prüft einen unabhängig bezogenen Bootstrap-SHA-256 vor der Ausführung. | `curl --insecure ... \| sh` ist bei kompromittiertem DNS/TLS/Serving vollständig angreifbar. Ein Digest aus derselben HTTP-Antwort ist kein unabhängiger Beweis. Nur der Weg Download–Prüfen–Ausführen reduziert diese Grenze. |
| Manipulierter SSH-Hostkey | Der Endpunkt wird ohne Verbindung gebunden; Control- und Ziel-Ed25519-Key kommen ausschließlich aus einer über die Providerkonsole authentisierten lokalen Datei oder Provider-Attestation; eigene Known-Hosts-Pins; striktes Checking; Status darf nur vergleichen; Rotation verlangt erneut eine separat verifizierte Identität. | Ein kompromittiertes Serving oder Control kann einen widersprüchlichen Fingerprint melden und den Workflow stoppen, aber weder Pin noch Rotation autorisieren. Die Providerkonsole bleibt Teil der Trust-Zeremonie. |
| Symlink-, Path-Traversal- oder Rename-Swap der Release-Wurzel | Private feste Wurzeln, normalisierte relative Pfade, `O_NOFOLLOW`, Owner-/Mode-/Linkcount-Prüfung, Archive ohne Symlinks/Devices/`..`, atomare Renames, feste Component-Allowlist. Auch Operator-Release-Lock und Buildlog werden als Single-Link und durch Pfad-/FD-Identität gebunden. Übergeordnete Verzeichnisse der Release-Wurzel sind nur root-/dienst-eigen; beschreibbare Eltern benötigen Sticky-Semantik. Der Root-FD bleibt während Publish offen, und `dev/inode` wird vor jeder Commit-Grenze erneut gebunden. | Eine unsichere Datei- oder Verzeichnisstruktur und jeder Identitätswechsel blockieren den Lauf. Nicht „reparieren“, bevor Herkunft und Besitz geklärt sind. Ein Angreifer mit Root- oder vollständigem Dienst-UID-Zugriff bleibt außerhalb dieser Dateisystemgrenze. |
| Secrets in Logs | Remote-Logs haben ausschließlich endliche Ereignis-/Codefelder; lokale Installer-Logs sind root-only, begrenzt und redigiert; PBP-Logs `0600`; keine freien Serverfehlermeldungen an Clients. | Heuristische Redaction ist keine Erlaubnis, Secrets auszugeben. Explizite Reveal-/Exec-Ausgaben und lokale Root-Logs müssen weiter als sensibel behandelt werden. |
| Secrets in Prozessliste oder Shell-History | Enrollment- und Mullvad-Eingaben über TTY/stdin; keine Secret-Flags, URLs oder Umgebungsvariablen; `set +x`; private Dateien. | `flow instance exec` setzt den bewusst gewählten Remote-Befehl in den SSH-Aufruf. Niemals Secrets in dessen Argumente schreiben. |
| Parallele Enrollment-Konsumenten | Exklusiver Store-Lock und atomare Consume-Transaktion. | Genau ein Gewinner; andere erhalten eine generische Ablehnung ohne Secretzustand. |
| Parallele Installationen | Root-eigener, `0600`, nicht blockierender `flock`; zusätzlich plan-/instanzgebundenes Reconcile-Journal. | Ein zweiter Lauf endet als `apply_busy`; Lockdatei nicht löschen. Prozess und Journal prüfen, dann denselben Plan erneut ausführen. |
| Abbruch während der SSH-Umschaltung | Schlüssel werden vor der Policy-Aktivierung installiert; effektive sshd-Policy und exakte `authorized_keys` werden verifiziert; bei einem Fehler werden SSH-Dienste deaktiviert. | Der Netzwerkzugriff kann absichtlich verloren gehen. Recovery nur über Providerkonsole oder einen bereits verifizierten Pfad; kein Passwort-/Root-Fallback. |
| Abbruch während der VPN-Umschaltung | Vorprüfungen, festes Transport-/Egressziel, Mullvad-Lockdown; der Rollback schaltet Auto-Connect aus, Lockdown an und trennt. | Providerkonsole erforderlich. Lockdown nicht aus Bequemlichkeit abschalten; erst Ursache und deutschen Egress prüfen. |
| Serving-Ausfall | Installierter Zustand und Checkpoint bleiben; keine unsignierten/gemischten Fallback-Releases; ein fester persistenter Fünf-Minuten-Timer startet ausschließlich den signierten One-shot-Reconcile. | Neue Enrollments, Apply, Status und Log-Upload fallen aus. Nach der Wiederkehr setzt der Timer fort; bis zum echten Reboot-/Ausfalltest bleibt diese Verfügbarkeitseigenschaft ein Release-Gate. |
| Serving startet SSH zu Ziel-VMs | Die öffentliche API hat keinen Job-/Exec-Endpunkt; der normale CLI-Lifecycle ruft weder SSH noch Prozesse auf; ein statisches Release-Gate prüft diese Route. | Ein Netzwerk-E2E muss zusätzlich belegen, dass vom Serving-Host keine Ziel-SSH-Verbindung ausgeht. |
| Allgemeiner Root-RCE-Kanal | Kein Pull-Jobmechanismus; die Runtime kennt nur signierte Profile und feste Executoren. Beliebige Befehle existieren nur als lokaler, expliziter `flow instance exec` über eine gebundene Control-Route und Ende-zu-Ende-Zielauthentisierung. `flow test lab` besitzt nur eine feste Action-Allowlist mit Payload-Digest, Ausgabegrenze und Timeout. | Wer Operator-SSH-Key und lokalen Operator-Account kompromittiert, kann den sichtbaren gerouteten Pfad nutzen. Das Exec-Audit enthält Ziel, Route, Zeit, argc und argv-Digest; das Lab-Audit enthält Ziel, feste Action und Payload-Digest. |
| Terminal-Escape-/Log-Injection | Remote-Felder sind größenbegrenzt und schemavalidiert; TUI und CLI neutralisieren C0/C1-, OSC- und Escape-Sequenzen; technische Rohdetails bleiben in nur für den Owner lesbaren Logs. | Unbekannte oder ungültige Terminaldaten werden sichtbar ersetzt und dürfen keine Aktion, Zwischenablage oder Anzeigezustand steuern. |
| Mullvad-Relay-Ausfall | Start nur nach verifiziertem Mullvad-Egress; PBP überwacht fortlaufend; begrenztes exponentielles Backoff mit Jitter; zwei Erfolge zur Wiederfreigabe. | Der Browser wird offline geschaltet und nach ausgeschöpfter Grace beendet. Kein blinder Auto-Restart; der Betreiber behebt das VPN und startet bewusst neu. |
| Falscher/nichtdeutscher Egress | Status plus IPv4-HTTPS-Check mit `mullvad_exit_ip=true` und `country=Germany`; der PBP-spezifische Graph erzwingt DE/Shadowsocks 443/Lockdown. | Der Context wird sofort offline geschaltet und kontrolliert beendet. Ein Relay-/IP-Wechsel beendet ebenfalls, weil die materialisierte WebRTC-IP sonst inkonsistent wäre. |
| Ausfall des Mullvad-Prüf-Endpunkts | Temporäre Fehler werden von positiv falschem Egress unterschieden; nur ein kurzes begrenztes Offline-/Retry-Fenster. | Der externe Endpoint kann PBP per DoS schließen. Kein alternativer ungeprüfter Egress wird zugelassen. |
| PBP-Browser-/Playwright-Crash | Der Dispatcher wird regelmäßig gepumpt; Page-, Context-, Process-, Signal- und Egress-Ende getrennt klassifiziert; stderr in rotiertem, bereinigtem JSONL; sichtbarer Desktop-Dialog. | Die ursprüngliche Ursache eines realen Browserendes bleibt ohne VM-Evidenz offen. AppArmor, OOM, Coredump, VNC/XFCE und Journal müssen im Realtest untersucht werden. |
| Veralteter PBP-App-/Browser-Lock | Kernel-`flock` immer im Cleanup; native Locks nur unter App-Lock und nur ohne exakten Profilprozess; PID plus Startzeit; begrenztes TERM/KILL. | Ein unklarer oder noch lebender Besitzer blockiert sicher. Locks nie blind löschen. |
| Unbemerkter Persona-Wechsel | Root-eigene Persona-ID, VM-weit stabiler Profilpfad, Schema-/Hashprüfung vor und nach Apply, der Checkpoint bindet die Persona; die v0.1.7-Migration erhält die Werte. | Eine unklare/inkompatible Persona blockiert. Recovery aus einem zusammengehörigen Snapshot, niemals Datei löschen und neu würfeln. |
| Öffentlicher VNC-Port / Zwischenablage | TigerVNC nur auf `127.0.0.1`/`::1`, die Laufzeitprüfung verlangt IPv4-Loopback und verbietet andere Listener; SSH `PermitOpen`; Zwischenablage standardmäßig aus. | Ein bereits kompromittierter VM-Benutzer könnte einen zweiten Server auf einem anderen Port starten. Eine Inbound-Firewall bleibt eine separate Pflicht. |
| VNC-Passwortleck | Root-Datei `0600`; die normale Ausgabe enthält es nicht; Reveal/Rotate nur explizit über gepinntes SSH mit Warnung und Audit; die Rotation prüft den Listener und stellt bei Fehler wieder her. | Der bewusste Reveal erscheint in stdout/JSON und kann durch Terminalaufzeichnung oder Automation geleakt werden. Nicht pipen oder persistieren. |
| AppArmor-Umgehung für Camoufox | PBP installiert nur bei Bedarf ein versionsgebundenes Profil mit zusätzlicher `userns`-Erlaubnis; die globale Sperre bleibt; kein `--no-sandbox`. | Kernel-/AppArmor-Änderungen können den Browser blockieren. Ein Denial ist sicherer, als User Namespaces global freizugeben. |

## Besonderes Restrisiko: Status ist nicht Ende-zu-Ende gespeichert

Die Instance Identity signiert Methode, Pfad, Body, Timestamp und Nonce des
Status-POST. Serving verifiziert diese Hülle, speichert danach aber nur den
normalisierten `StatusReport`. Beim Control-GET erhält der Operator keine
erneut prüfbare Instance-Signatur. Ein Serving-root kann daher Statusfelder auf
der Disk oder in der Antwort ändern.

Das ist für die Apply-Autorisierung unschädlich, weil Release und Desired State
separat signiert sind. Auch der erste SSH-Trust ist davon getrennt: Ohne eine
über die Providerkonsole authentisierte Datei und den expliziten Befehl
`flow instance hostkey pin` bleibt SSH blockiert. `flow instance status`
übernimmt keinen Key; es vergleicht den gemeldeten Wert nur mit einem
vorhandenen Pin. Ein kompromittiertes Serving kann daher die Observability
verfälschen oder einen Widerspruch/DoS erzeugen, aber SSH nicht auf einen neuen
Key umlenken.

Für die noch freizugebende Remote-Route gilt zusätzlich: Bis Statusberichte
Ende-zu-Ende signiert gespeichert und vom Operator verifiziert werden, ist die
folgende Trust-Zeremonie erforderlich. Sie hebt das aktuelle Route-Gate nicht auf:

1. Den initialen Hostkey ausschließlich über die Providerkonsole oder einen
   anderen authentisierten Kanal als lokale reguläre Datei beziehen;
2. den Endpunkt binden und mit
   `flow instance hostkey pin NAME --public-key-file ...` netzwerklos pinnen;
3. erst danach den Status vergleichen und SSH verwenden;
4. Änderungen nur nach erneuter unabhängiger Prüfung mit
   `flow instance hostkey rotate NAME --public-key-file ...` akzeptieren.

## Sicherheitsinvarianten und Release-Gates

- Kein privater Key und kein Mullvad-/VNC-Secret ist in Git, Release,
  Serving-State oder Prozessargumenten. Das Enrollment-Secret erscheint
  ausschließlich bei `flow enroll create` bewusst einmalig in der
  Operator-Ausgabe und wird danach weder lokal noch auf Serving im Klartext
  gespeichert; andere normale Befehle geben es nicht aus.
- Falsche Signatur, ein geändertes Byte, falsches Target, abgelaufener Desired
  State, Rollback oder widerrufene Komponente stoppt vor der Aktivierung.
- Der Serving-Lifecycle initiiert kein SSH; Enrollment und Installation
  benötigen auf der Ziel-VM grundsätzlich nur ausgehendes HTTPS.
- PBP erzeugt keinen Browser vor bestätigtem deutschem Mullvad-Egress und wird
  bei falschem/verlorenem Egress fail-closed.
- Normales Schließen, SIGKILL und Launcher-Abbruch geben Locks frei; ein
  Neustart ändert die Persona nicht.
- VNC-Port 5901 ist nach Apply und Reboot ausschließlich Loopback.

Lokale Tests unterstützen diese Invarianten, ersetzen aber nicht:

- den Vier-VM-E2E-Lauf;
- den tatsächlichen Reboot-/Resume-Nachweis;
- fünf reale PBP-Schließen-/Neustartzyklen;
- einen Wall-Clock-Soak von mindestens 1800 Sekunden;
- einen echten Mullvad-Disconnect-/Reconnect-Test auf einer Wegwerf-VM.

## Übergreifende Restrisiken

- Ein kompromittierter Operator-Rechner kann gültige bösartige Releases und
  Desired States signieren und alle dort gespeicherten SSH-Keys verwenden.
  Offline-/hardwaregestütztes Signing ist empfohlen, derzeit aber nicht
  erzwungen.
- Der Quickstart vertraut initial TLS/Serving. Nur ein unabhängig bezogener
  Bootstrap-Digest oder ein bereits vertrauenswürdig installiertes
  `flow`-Binary entfernt diese konkrete Abhängigkeit vom Erstdownload.
- Ein kompromittiertes Ziel-root kann Status lügen, Persona/Logs lesen und die
  lokale Runtime umgehen. Dynamicflow ist kein Schutz vor root auf derselben VM.
- Browser-Fingerprinting ist probabilistisch. PBP verspricht eine stabile,
  intern konsistente Persona und Fail-closed-Egress, keine mathematische
  Anonymitätsgarantie.
- Mullvad und sein Check-Endpunkt können die Verfügbarkeit verhindern. Ein
  sicherer Fallback auf unbestätigten Egress existiert absichtlich nicht.
