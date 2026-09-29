# ADR 0002: Control-first-Terminalplattform und providerneutraler Bootstrap

- Status: angenommen
- Datum: 23.07.2026
- Ersetzt: ADR 0001, Abschnitte 2, 4, 8 und 10, soweit dort direkte
  Operator-Verbindungen zu `serving` oder `instance` beschrieben werden

## Kontext

ADR 0001 trennte Signaturen, Enrollment, unveränderliche Releases und die
Target-Runtime erfolgreich. Sein Netzmodell erlaubt dem Operator aber eine
direkte HTTPS-Verbindung zu `serving` und direkte, gepinnte SSH-Verbindungen zu
Instanzen. Der neue Produktvertrag ist strenger: Nach dem einmaligen Bootstrap
des ersten Control-Knotens darf der Operator ausschließlich verifizierte
Control-Knoten kontaktieren.

Der bisherige Name `control` bezeichnet in Code und State außerdem einen
Ed25519-Schlüssel für Serving-Admin-Requests. Dieser Schlüssel ist weder ein
Control-Knoten noch eine Control-Route. Die Namenskollision könnte eine direkte
Operator-zu-Serving-Verbindung fälschlich wie einen Control-first-Pfad aussehen
lassen.

## Entscheidung

### 1. Vier getrennte Ebenen

Dynamicflow trennt:

1. **Operator:** lokale TUI/CLI, Offline-Vertrauenswurzeln und private
   Ende-zu-Ende-SSH-Schlüssel;
2. **Control:** gehärteter SSH-Transport, Routing und Policy Enforcement;
3. **Serving:** HTTPS-Verteilung, Enrollment und Zustandskoordination;
4. **Instance:** pull-basierte One-shot-Reconciliation eines signierten Profils.

Der bisherige Serving-Admin-Signierschlüssel wird in neuen Schemas und
Benutzertexten `serving-admin` genannt. Alte `control.*.pem`-Pfade werden erst
nach einer expliziten, atomaren Migration ersetzt; ihre Rolle wird niemals als
Control-Knotenidentität interpretiert.

### 2. Verbindliche Netzpfade

| Phase / Aktion | Erlaubter Pfad |
| --- | --- |
| Erstes Control-Bootstrap | Operator → Control, erst nach unabhängiger Hostkey-Bestätigung |
| Jede spätere Operatoraktion | Operator → verifiziertes Control |
| Serving-/Instance-Bootstrap | Operator → Control → Ziel |
| SSH, Exec, VNC, Diagnose | Operator → Control → Ziel, Zielauthentisierung Ende-zu-Ende |
| Desired State, Release, Status, Logs | Instance → Serving über ausgehendes HTTPS |
| Serving-Administration | Operator → Control → Serving-HTTPS |
| Notfall | Explizite, auditierte Providerkonsole außerhalb von `flow` |

Nach dem Zustand `control_ready` werden direkte Operator-Sockets zu Serving-
oder Instance-Endpunkten bereits vor der DNS-Auflösung beziehungsweise dem
Prozessstart abgelehnt. Es gibt keinen direkten Fallback bei Control-Ausfall.
Serving initiiert nie SSH.

Control erhält keine langfristigen privaten Zielschlüssel. OpenSSH
`ProxyJump`/stdio-Forwarding transportiert die lokale Ende-zu-Ende-
Authentisierung; Agent-, X11- und unkontrolliertes TCP-Forwarding bleiben aus.
VNC erlaubt ausschließlich den festen Loopback-Forward zum gepinnten Ziel.

### 3. Providerneutrale Greenfield-Zeremonie

`flow system init` erzeugt lokal ein schemaversioniertes System, getrennte
Signierwurzeln und genau eine neue Bootstrap-Identität für den ersten
Control-Knoten. Die TUI zeigt nur den Public Key und die VM-Anforderungen. Die
Providerkonsole bleibt der menschliche Provisionierungsschritt.

Vor dem ersten Socket verlangt flow Host, SSH-Benutzer, OS und einen unabhängig
bezogenen Ed25519-Host-Public-Key. Ein injizierter Client-Public-Key
authentisiert die VM nicht. TOFU und `ssh-keyscan` sind keine Trust-Quellen.

Der Workflow ist als persistente Task mit diesen Commit-Gates modelliert:

```text
system_ready
  -> control_key_ready
  -> control_endpoint_bound
  -> control_hostkey_verified
  -> control_installing
  -> control_ready
  -> serving_key_ready
  -> serving_ready
```

Jede weitere VM besitzt ihre eigene Bootstrap-Identität und dieselben
Endpoint-/Hostkey-Gates. Nach der Installation des verwalteten Keys wird der
Bootstrap-Key erst nach einem positiven Ende-zu-Ende-Beweis entfernt und lokal
als widerrufen markiert.

Provideradapter dürfen dieselben Eingaben liefern, ändern aber weder State
Machine noch Trust-Gates.

### 4. Gemeinsame Application Services

TUI, menschenlesbare CLI und `--json` rufen dieselben Application Services auf.
Command-Parser oder TUI-Modelle dürfen keine eigenen Netzwerk-, Signing- oder
State-Übergänge implementieren. Ein Service liefert typisierte Resultate,
Phasen und nächste erlaubte Aktionen; Renderer entscheiden nur über die
Darstellung.

`flow` ohne Argument öffnet auf einem TTY die TUI. Ohne TTY scheitert der
Aufruf eindeutig und verweist auf CLI/`--json`; er fällt nicht still auf Help
oder einen interaktiven Secret-Prompt zurück.

### 5. Persistente Aufgaben

Lange und menschlich unterbrochene Vorgänge besitzen ein nur für den Owner
lesbares Task-Journal. Jeder Eintrag bindet System, Ziel, Aktion, Route,
erwartete Identitäten, Plan-Digest, Phase, Ergebnis und Zeit. Übergänge
erfolgen unter einem nicht blockierenden Lock und per atomarem Replace. Nach
einem Neustart wird aus dem letzten bestätigten Gate fortgesetzt; irreversible
Schritte werden nicht blind wiederholt.

Freitext von Remotesystemen wird nie ungeprüft als Terminalsteuersequenz
gerendert. Logs und Fehler haben feste Codes, begrenzte Felder und einen nur für
den Owner lesbaren Detailpfad.

### 6. Control-Mesh

Ein System startet mit genau einem Control-Knoten. Weitere Knoten treten über
eine explizit signierte, zweiphasige Mitgliedschaft bei:

```text
candidate -> identity_verified -> reachable -> active
```

Routen binden Aktion, Ziel, Control-ID, Control-Hostkey und Ziel-Hostkey.
Failover wählt nur einen aktiven, gesunden und für die Aktion autorisierten
Knoten. Es darf keine Hostkey-, Berechtigungs- oder Zielprüfung abschwächen.
Bei widersprüchlicher Mitgliedschaft oder ohne sichere Route gilt
`route_unavailable` und fail-closed.

### 7. Rotation und Ersatz

Control-, Serving-, Instance-, SSH-, Hostkey-, TLS-, Signing-, Enrollment- und
VNC-Identitäten verwenden grundsätzlich:

```text
prepare/overlap -> verify -> switch -> revoke old
```

Der vorherige Zustand bleibt bis zum verifizierten Switch wiederaufnehmbar.
Eine alte Identität wird nicht allein aufgrund verstrichener lokaler Zeit
entfernt. Hostkey- oder Trust-Root-Wechsel benötigen erneut eine unabhängige
Bestätigung beziehungsweise ein explizites Multi-Key-Migrationsdokument.

## Sicherheitsinvarianten

- Nach `control_ready` kann kein normaler Operatorcode einen direkten
  Serving-/Instance-Dial oder ein direktes SSH-Ziel konstruieren.
- Der einzige direkte SSH-Sonderfall ist das erste, unabhängig verifizierte
  Control-Bootstrap.
- Serving besitzt keine Release-, Desired-State- oder Ziel-SSH-Private-Keys.
- Control besitzt keine langfristigen Ziel-SSH-Private-Keys.
- Private Schlüssel, Enrollment- und MFA-Secrets erscheinen nie in URL, argv,
  Prozessumgebung, Log oder TUI-State-Snapshot.
- Eine Instanz installiert nur einen signierten, instanz- und profilgebundenen
  Pull-Desired-State.
- Eine fehlende sichere Route, fehlende Identitätsbestätigung oder ein
  widersprüchlicher Mesh-Zustand stoppt vor jeder Netzaktivität.

Diese Invarianten werden mit Unit-, CLI-/TUI-Vertrags- und negativen
Netzwerktests geprüft. Ein Test, der nur das Fehlen eines dokumentierten
Direktbefehls feststellt, reicht nicht; ein instrumentierter Dial-/Prozess-
Recorder muss den tatsächlich gewählten ersten Hop beweisen.

## Konsequenzen

- Bestehende direkte `remoteServing`-Clients und `instances.SSHArgs` sind
  Migrationsquellen, keine gültigen finalen Operatorpfade.
- `flow start serving` bleibt für die interne Rolle idempotent, wird vom
  Operator aber nur als control-geroutete Operation ausgelöst.
- Ein Control-Ausfall reduziert die Verfügbarkeit, niemals die
  Trust-Anforderungen.
- Der Provider muss keine API anbieten. Der Mensch kann VMs weiter in jeder
  Cloud-Konsole erstellen und den von flow erzeugten Public Key einfügen.
- Die TUI ist kein Wrapper um CLI-Subprozesse; beide Oberflächen teilen die
  fachlichen Services.

## Noch offene Nachweise

Diese ADR erteilt keine Produktionsfreigabe. Erforderlich bleiben der echte
Greenfield-, Replacement- und Mesh-Lauf auf vier freigegebenen Cloud-VMs sowie
PBP-Forensik, mindestens 30 Minuten Wall-Clock-Soak, Neustartzyklen und echter
VPN-Failover.
