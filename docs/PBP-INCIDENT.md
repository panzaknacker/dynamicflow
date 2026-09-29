# PBP-P0: Browserende, veralteter Launcher und sichtbare Recovery

Stand: 23.07.2026

## Beobachtetes Szenario

- Debian 13 amd64;
- SSH/GUI `v0.1.6`;
- PBP `v0.1.7`;
- GUI-Benutzer `malwarelab`;
- Mullvad Deutschland, Shadowsocks Port 443, Lockdown und Auto-Connect;
- deutscher Egress funktionierte nach dem Relaywechsel Berlin → Frankfurt;
- Camoufox startete und war zunächst bedienbar;
- nach einigen Minuten schloss der Browser;
- ein weiterer Klick auf den Desktop-Eintrag zeigte nichts Brauchbares.

Zwei Vorgänge müssen getrennt werden:

1. Warum endete der erste Browserprozess nach einigen Minuten?
2. Warum blieb der zweite Start unsichtbar blockiert?

Nur der zweite Vorgang ist aus dem v0.1.7-Code deterministisch erklärt. Eine
VM-spezifische Ursache für den ersten Browserexit darf ohne neue Evidenz nicht
behauptet werden.

## Bestätigte Ursache des unsichtbaren Neustartfehlers

PBP v0.1.7 registrierte beim synchronen Playwright-Context einen
`context.on("close", ...)`-Callback und wartete danach im Hauptthread nur mit
`threading.Event.wait(0.5)`.

Die gepinnte synchrone Playwright-Laufzeit liefert Callbacks über ihr
Dispatcher-Greenlet aus. Dieses wird durch synchrone Playwright-Aufrufe
gepumpt, nicht durch `threading.Event.wait()`. Damit konnte Folgendes passieren:

1. Browser oder Context schließt;
2. das Close-Ereignis wartet im Dispatcher;
3. der Python-Launcher bleibt am Event-Wait hängen;
4. der Launcher hält weiterhin den Kernel-`flock` auf `browser.lock`;
5. der nächste Launcher erkennt korrekt „bereits aktiv“ und beendet sich;
6. der Desktop-Eintrag hatte `Terminal=false` und keinen Dialogpfad, also
   verschwand die Fehlermeldung für den Benutzer.

Das erklärt den veralteten App-Lock und den lautlosen zweiten Start. Es erklärt
nicht den vorausgehenden ersten Browserexit.

## Implementierte Korrektur in PBP v0.1.8

### Playwright und Prozesse

- Der Launcher pumpt den synchronen Dispatcher mindestens alle 250 ms über
  ein begrenztes Playwright-Event-Wait.
- Page-Close, Page-Crash, unerwartetes Context-Close, Signal, Relaywechsel und
  Egress-Abbruch werden getrennt klassifiziert.
- Der App-Lock wird in jedem Exitpfad geschlossen.
- Native Firefox-Locks werden nur unter gehaltenem App-Lock, nur nach
  nachweislich fehlendem Profilprozess und mit Race-Prüfung entfernt.
- Der Prozess-Cleanup betrifft ausschließlich den exakten PBP-Profilbaum. PID
  und Prozessstartzeit werden vor TERM und vor begrenztem KILL erneut
  verglichen.
- Es gibt keinen blinden Auto-Restart.

### Sichtbarkeit und Logs

- Jeder Start erzeugt ein bereinigtes, begrenztes JSONL-Log unter
  `/home/malwarelab/.local/state/dynamicflow/pbp/logs/runtime-*.jsonl`.
- Verzeichnis `0700`, Dateien `0600`, höchstens acht Runtime-Logs, höchstens
  4 MiB je Datei.
- Browser-stderr und interne Tracebacks werden über einen privaten fd
  aufgenommen und vor der Speicherung bereinigt.
- Der Desktoppfad zeigt bei einem Fehler einen `zenity`-Dialog, danach sichere
  Fallbacks über `xmessage`/`notify-send`, mit konkreter Handlung und Logpfad.

### VPN fail-closed

- Vor dem Browserstart muss der IPv4-Check Mullvad und `country=Germany`
  bestätigen.
- Während der Sitzung schaltet ein definitiv falscher Egress den Context
  sofort offline und beendet ihn.
- Ein temporärer Endpoint-Ausfall führt zunächst offline in ein begrenztes
  exponentielles Backoff mit Jitter.
- Erst zwei aufeinanderfolgende Erfolge schalten wieder online.
- Nach ausgeschöpftem Backoff wird beendet. Ein Relay-/IP-Wechsel beendet
  ebenfalls kontrolliert, weil die beim Start materialisierte WebRTC-IP sonst
  inkonsistent wäre.

### Stabile Persona

- Persona: `/etc/toolkit/pbp-persona.json`, root:root `0644`, Schema 2 und
  inhaltlich validierte `persona_id`.
- Profil: `/home/malwarelab/.local/share/toolkit-pbp/profile`.
- Die v0.1.7-Persona und das zugehörige Profil werden strukturerhaltend
  migriert; Preset, Seeds, Fonts, Voices, Prefs und Profildaten werden nicht neu
  gewählt.
- Der Target-Checkpoint merkt sich die Persona-ID und prüft sie vor und nach
  dem Apply.
- Unklare oder inkompatible Daten blockieren, statt still eine neue Persona zu
  erzeugen.

## Noch offene Ursache des ersten Browserendes

Der ursprüngliche VM-Lauf lieferte noch kein neues Runtime-Log mit
klassifiziertem Ende. Folgende Hypothesen bleiben deshalb offen und sind im
Realtest anhand von Belegen zu unterscheiden:

- Camoufox-/Firefox-Crash oder Coredump;
- OOM-Kill oder anderer Kernel-Kill;
- AppArmor-/User-Namespace-Denial;
- Ende/Reset der XFCE-/TigerVNC-/X11-Sitzung;
- Signal durch Benutzer, Service oder Provider;
- Mullvad-Egress-/Relaywechsel;
- Playwright-Context- oder Page-Crash.

„Wahrscheinlich AppArmor“, „wahrscheinlich VPN“ oder „Camoufox instabil“ ist
ohne passende Journal-/Runtime-Evidenz keine Ursachenfeststellung.

## Evidenzplan auf der echten VM

| Bereich | Beleg | Erwartete Aussage |
| --- | --- | --- |
| Browserprozess | PID, PPID, Startzeit, exakter Profilparameter, Exit/SIGKILL | Nur Prozesse des stabilen PBP-Profils werden zugeordnet |
| Playwright | Runtime-Events für Page/Context/Process | Ende ist klassifiziert; Dispatcher läuft |
| App-Lock | Zweiter Start während des Laufs und nach dem Ende | Sichtbarer Dialog während des Laufs; Lock danach wieder erwerbbar |
| Native Locks | `lock`, `.parentlock`, `parent.lock` plus Prozessprüfung | Nur nachweislich veraltete Locks entfernt |
| Persona/Profil | Persona-ID vor/nach, Profilpfad, sichere Owner/Modes | Keine stille Ersetzung |
| Mullvad | Status, Germany-Egress, Offline/Retry/Recovery | Kein Browser bei falschem Egress; begrenztes Backoff |
| Desktop | Echter Klick/WM_DELETE und Dialogfenster | Kein lautloser Fehler |
| VNC/XFCE | Dienst, DISPLAY/XAUTHORITY, Listener, Journal | Sitzungsverlust von Browsercrash unterscheidbar |
| AppArmor/Kernel | `ausearch`, Kerneljournal, OOM/Denials | Denial/Kill belegt oder ausdrücklich nicht verfügbar |
| Crash | `coredumpctl list/info` | Nativer Crash belegt oder kein Coredump vorhanden |
| stderr | Bereinigtes Runtime-JSONL | Technische Ursache ohne Secret-/IP-Leak |

Rohdaten können IP-Adressen und andere Metadaten enthalten. Sie bleiben
root-/benutzerprivat; in den Testabschluss gelangen nur bereinigte Codes,
Zeitpunkte und Booleans.

## Lokale Regressionen versus Realtest

Die lokalen Tests decken unter anderem ab:

- simulierte 30 Minuten als 7200 Dispatcher-Takte;
- mehrfaches normales Schließen/Neustarten;
- erneutes Erwerben des Locks;
- Prozess- und Native-Lock-Cleanup;
- Relaywechsel und Egress-Backoff;
- Persona-Migration/-Stabilität;
- sichtbare Fehlerpfade und Log-Redaction.

Diese Tests beweisen Codepfade, aber weder Wall-Clock-Stabilität noch VNC,
Kernel, AppArmor, Mullvad oder Camoufox auf der echten VM.

## Qualifizierender Realtest

Der Harness `pbp/tests/pbp-vm-soak.py` hat keinen Mock-PASS-Pfad. Er wird als
`malwarelab` in einem Terminal der realen XFCE-/VNC-Sitzung mit ihrem echten
`DISPLAY` und `XAUTHORITY` gestartet:

```sh
python3 ./pbp-vm-soak.py \
  --duration-seconds 1800 \
  --normal-cycles 5 \
  --exercise-vpn-failure \
  --disposable-network-test
```

Die beiden VPN-Flags sind eine doppelte Freigabe für einen realen
Mullvad-Disconnect/-Reconnect und können SSH/VNC unterbrechen. Nur auf einer
ausdrücklich als disposable markierten VM mit Providerkonsole verwenden.

Der Test verlangt:

- mindestens 1800 Sekunden Wall Clock;
- fünf reale WM_DELETE-Schließen-/Neustartzyklen;
- sichtbare Ablehnung eines parallelen Starts;
- Browser-SIGKILL, klassifiziertes Ende und sichtbaren Dialog;
- keine Profilprozesse oder gehaltenen Locks nach jedem Ende;
- dieselbe Persona-ID vor/nach allen Zyklen;
- sichere, getrennte und redigierte Runtime-Logs;
- echten VPN-Disconnect, beobachtetes Offline/Backoff/terminales Fail-closed;
- wiederhergestellten deutschen Mullvad-Egress für den Abschluss.

Ergebnisdateien liegen standardmäßig unter
`/home/malwarelab/.local/state/dynamicflow/pbp/test-results/`, Modus `0600`,
ohne IP, Persona-Hash, URL oder Secret. Exitcodes: `0=PASS`, `1=FAIL`,
`2=BLOCKED`, `130=unterbrochenes BLOCKED`.

Ein Kurzlauf mit `--duration-seconds 60 --allow-short-nonqualifying` darf nur
die Verdrahtung prüfen und bleibt immer `BLOCKED`.

## Aktueller Evidenzstatus

| Gate | Status |
| --- | --- |
| Ursache des veralteten v0.1.7-Locks im Code reproduziert | Lokal deterministisch belegt |
| v0.1.8 Unit-/Lifecycle-Regressionen | Lokal implementiert; Ergebnis im Abschlussbericht erneut erfassen |
| Ursache des ursprünglichen ersten Browserendes | Offen, bis echte VM-Evidenz vorliegt |
| Reale fünf Schließen-/Neustartzyklen | Noch nicht ausgeführt/dokumentiert |
| Reale mindestens 30 Minuten | Noch nicht ausgeführt/dokumentiert |
| Echter VPN-Fail-closed-/Reconnect-Lauf | Noch nicht ausgeführt/dokumentiert |

Ohne die letzten drei Gates darf der PBP-P0 nicht als vollständig geschlossen
gemeldet werden.
