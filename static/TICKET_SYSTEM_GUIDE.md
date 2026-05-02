# Ticket-System Handbuch

## Übersicht

Das Enhanced Ticket System bietet eine flexible und leistungsstarke Lösung für das Ticket-Management in InventoryApp. Es unterstützt benutzerdefinierte Workflows, SLA-Regeln, Custom Fields und vieles mehr.

## Funktionen

### 1. Kategorien

Ticket-Kategorien ermöglichen die Organisation von Tickets nach Themengebieten.

**Einstellungen:**
- **Name**: Eindeutiger Name der Kategorie
- **Beschreibung**: Optionale Beschreibung
- **Farbe**: Hex-Farbcode für visuelle Unterscheidung
- **Icon**: Bootstrap Icon-Name (z.B. 'bug', 'gear')
- **Standard SLA**: Standard-Bearbeitungszeit in Stunden
- **Standard-Bearbeiter**: Optional zugewiesener Benutzer

**Verwendung:**
1. Navigieren Sie zu Ticket-Einstellungen → Kategorien
2. Klicken Sie auf "Neue Kategorie"
3. Füllen Sie die erforderlichen Felder aus
4. Speichern Sie die Kategorie

### 2. Prioritäten

Prioritäten definieren die Dringlichkeit von Tickets.

**Einstellungen:**
- **Name**: Prioritätsbezeichnung (z.B. "Hoch", "Mittel", "Niedrig")
- **Level**: Numerischer Wert (1-5, wobei 5 am höchsten ist)
- **Farbe**: Visuelle Hervorhebung
- **Response Time**: Erwartete Antwortzeit in Stunden
- **Resolution Time**: Erwartete Lösungszeit in Stunden
- **Auto-Eskalation**: Automatische Eskalation bei Überschreitung

**Best Practices:**
- Definieren Sie 3-5 Prioritätsstufen
- Setzen Sie realistische Zeiten
- Höhere Prioritäten sollten kürzere Zeiten haben

### 3. Status & Workflows

Status-Workflows steuern den Lebenszyklus eines Tickets.

**Standard-Status:**
- **new**: Neu erstellt
- **open**: In Bearbeitung
- **pending**: Wartet auf Rückmeldung
- **resolved**: Gelöst
- **closed**: Geschlossen

**Workflow-Übergänge:**
Definieren Sie erlaubte Statusübergänge in der `allowed_next_statuses` Spalte als JSON-Array.

Beispiel:
```json
["open", "pending", "resolved"]
```

### 4. Custom Fields

Erstellen Sie benutzerdefinierte Felder für zusätzliche Ticket-Informationen.

**Feldtypen:**
- **text**: Einzeiliger Text
- **number**: Numerische Werte
- **date**: Datumsauswahl
- **select**: Dropdown mit vordefinierten Optionen
- **checkbox**: Ja/Nein-Wert

**Optionen für Select-Felder:**
Speichern Sie Optionen als JSON-Array:
```json
["Option 1", "Option 2", "Option 3"]
```

### 5. Vorlagen

Ticket-Vorlagen beschleunigen die Erstellung häufiger Ticket-Typen.

**Platzhalter in Vorlagen:**
- `{user}`: Name des Erstellers
- `{date}`: Aktuelles Datum
- `{time}`: Aktuelle Uhrzeit
- `{item_id}`: ID des betroffenen Gegenstands (falls zutreffend)

**Beispiel-Vorlage:**
```
Titel: Hardware-Problem - {item_id}
Beschreibung:
Betroffener Gegenstand: {item_id}
Gemeldet von: {user}
Datum: {date}

Problembeschreibung:
[Bitte beschreiben Sie das Problem]
```

### 6. SLA-Regeln

Service Level Agreements definieren Bearbeitungszeiten und Eskalationen.

**Regel-Priorität:**
SLA-Regeln werden in dieser Reihenfolge angewendet:
1. Spezifische Kategorie + Spezifische Priorität
2. Nur spezifische Kategorie
3. Nur spezifische Priorität
4. Standard-SLA

**Eskalation:**
- **Notify Before Breach**: Benachrichtigung X Stunden vor Fristablauf
- **Escalate on Breach**: Ticket automatisch an anderen Benutzer zuweisen
- **Escalate To**: Ziel-Benutzer für Eskalation

### 7. Zeiterfassung

Erfassen Sie die für Tickets aufgewendete Zeit.

**Felder:**
- **Minuten**: Aufgewendete Zeit
- **Beschreibung**: Beschreibung der Tätigkeit
- **Billable**: Abrechenbar (Ja/Nein)
- **Hourly Rate**: Stundensatz (optional)

### 8. Ticket-Verknüpfungen

Verknüpfen Sie verwandte Tickets miteinander.

**Link-Typen:**
- **blocks**: Dieses Ticket blockiert ein anderes
- **blocked_by**: Dieses Ticket wird blockiert von einem anderen
- **relates_to**: Allgemeine Beziehung
- **duplicates**: Dieses Ticket ist ein Duplikat

### 9. Watcher

Benutzer können Tickets beobachten, um Benachrichtigungen zu erhalten.

**Benachrichtigungstypen:**
- **On Update**: Bei jeder Aktualisierung
- **On Response**: Bei neuen Kommentaren/Antworten
- **On Status Change**: Bei Statusänderungen

## Konfiguration

### Initialisierung

Das Ticket-System wird automatisch beim ersten Start der Anwendung initialisiert.

### Datenbank-Modelle

Die folgenden Tabellen werden erstellt:
- `ticket_category`: Kategorien
- `ticket_priority`: Prioritäten
- `ticket_status`: Status
- `ticket_custom_field`: Custom Fields
- `ticket_field_value`: Custom Field-Werte
- `ticket_template`: Vorlagen
- `ticket_sla`: SLA-Regeln
- `ticket_time_entry`: Zeiterfassung
- `ticket_link`: Ticket-Verknüpfungen
- `ticket_watcher`: Beobachter

### Berechtigungen

Stellen Sie sicher, dass folgende Berechtigungen korrekt konfiguriert sind:
- `view_tickets`: Tickets anzeigen
- `create_tickets`: Tickets erstellen
- `edit_tickets`: Tickets bearbeiten
- `delete_tickets`: Tickets löschen
- `manage_settings`: Ticket-System konfigurieren

## API-Endpunkte

### Kategorien
- `POST /tickets/api/category`: Kategorie erstellen
- `PUT /tickets/api/category/<id>`: Kategorie aktualisieren
- `DELETE /tickets/api/category/<id>`: Kategorie löschen

### Prioritäten
- `POST /tickets/api/priority`: Priorität erstellen
- `PUT /tickets/api/priority/<id>`: Priorität aktualisieren
- `DELETE /tickets/api/priority/<id>`: Priorität löschen

### Status
- `POST /tickets/api/status`: Status erstellen
- `PUT /tickets/api/status/<id>`: Status aktualisieren
- `DELETE /tickets/api/status/<id>`: Status löschen

### Custom Fields
- `POST /tickets/api/custom-field`: Custom Field erstellen
- `PUT /tickets/api/custom-field/<id>`: Custom Field aktualisieren
- `DELETE /tickets/api/custom-field/<id>`: Custom Field löschen

## Troubleshooting

### Tickets werden nicht angezeigt
- Prüfen Sie die Berechtigungen des Benutzers
- Stellen Sie sicher, dass das Ticket-Modul aktiviert ist

### SLA-Benachrichtigungen funktionieren nicht
- Prüfen Sie die E-Mail-Konfiguration in den System-Einstellungen
- Stellen Sie sicher, dass der Cronjob für SLA-Checks läuft

### Custom Fields werden nicht gespeichert
- Prüfen Sie, dass das Custom Field aktiv ist
- Stellen Sie sicher, dass Pflichtfelder ausgefüllt sind

## Best Practices

1. **Kategorien**: Halten Sie die Anzahl überschaubar (5-10)
2. **Prioritäten**: Definieren Sie klare Kriterien für jede Prioritätsstufe
3. **Status**: Beschränken Sie Workflows auf notwendige Übergänge
4. **Custom Fields**: Nur wirklich benötigte Felder erstellen
5. **SLA-Regeln**: Realistische Zeiten setzen
6. **Vorlagen**: Für häufige Ticket-Typen erstellen

## Support

Bei Fragen oder Problemen:
1. Prüfen Sie die Logs in `/app/logs/`
2. Konsultieren Sie die Online-Dokumentation
3. Öffnen Sie ein Support-Ticket

---

**Version:** 1.0
**Letzte Aktualisierung:** Dezember 2025
