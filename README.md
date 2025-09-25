# InventoryApp

Professionelle, leichtgewichtige Web-Applikation zur Bestandsverwaltung auf Basis von **Python** und **Flask**.  
Die Anwendung ermöglicht das Erfassen, Suchen und Verwalten von Artikeln – performant, übersichtlich und lokal oder serverseitig betreibbar.

---

## Highlights

- **Schnelle Bestandsverwaltung:** Anlegen, Bearbeiten, Löschen und Anzeigen von Artikeln  
- **Effiziente Suche & Filter** für große Datenmengen  
- **Saubere Architektur:** Trennung von Logik, Templates und statischen Assets  
- **Einfacher Betrieb:** Lokal in Minuten startklar, auf Servern per WSGI (gunicorn/uwsgi) betreibbar  
- **Erweiterbar:** Klar strukturierter Code, ideale Grundlage für kundenspezifische Features

> Hinweis: Abhängig vom aktuellen Repos-Stand können Funktionen leicht variieren. Diese Readme beschreibt das generische Setup der App.

---

## Technischer Überblick

- **Programmiersprache:** Python 3.12+  
- **Framework:** Flask  
- **Templates:** Jinja2 (`templates/`)  
- **Assets:** CSS/JS in `static/`  
- **Abhängigkeiten:** Siehe `requirements.txt`

---

## Systemvoraussetzungen

- Git
- Python **3.12** (oder neuer)
- Betriebssystem: Linux, macOS, Windows (WSL unterstützt)
- (Ubuntu/Debian) Paket für virtuelle Umgebungen: `python3.12-venv`

---

## Installation & Inbetriebnahme

### Linux / macOS / WSL

```bash
# 1) Repository klonen
git clone https://github.com/BoondockSulfur/InventoryApp.git
cd InventoryApp

# 2) Virtuelle Umgebung anlegen
python3 -m venv .venv
# Falls ensurepip/venv fehlt (Ubuntu/Debian):
#   sudo apt update && sudo apt install -y python3.12-venv
#   rm -rf .venv && /usr/bin/python3.12 -m venv .venv

# 3) Aktivieren
source .venv/bin/activate

# 4) Abhängigkeiten installieren
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# 5) Starten (Variante A: Flask CLI)
export FLASK_APP=app.py
export FLASK_ENV=development    # optional für Auto-Reload & Debug
flask run

# 5) Starten (Variante B: Direkt)
# python app.py

Die Anwendung ist anschließend unter http://127.0.0.1:5000
 erreichbar.
Alternativer Port: flask run -p 5050.

Windows (PowerShell)
# 1) Repository klonen
git clone https://github.com/BoondockSulfur/InventoryApp.git
cd InventoryApp

# 2) Virtuelle Umgebung anlegen & aktivieren
py -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3) Abhängigkeiten installieren
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# 4) Starten (Flask CLI)
$env:FLASK_APP="app.py"
$env:FLASK_ENV="development"    # optional
flask run

# Direktstart (Alternative)
# python app.py

Konfiguration

Nutzen Sie optional eine .env im Projekt-Root (wird von vielen Flask-Setups automatisch gelesen):

# Beispielwerte (anpassen)
FLASK_ENV=development
FLASK_DEBUG=1
SECRET_KEY=change-me


Empfehlungen:

SECRET_KEY in Produktion zwingend sicher, lang und zufällig setzen.

Debug/Development-Modus in Produktion deaktivieren.

Projektstruktur (typisch)
InventoryApp/
├─ app.py
├─ requirements.txt
├─ templates/          # HTML/Jinja2-Templates
├─ static/             # CSS/JS/Assets
└─ README.md


Die genaue Struktur kann je nach Commit-Stand abweichen.

Entwicklung

Auto-Reload via FLASK_ENV=development

Abhängigkeiten pflegen:

pip install <paket>
pip freeze > requirements.txt


Code-Qualität: Bitte Pull Requests mit klaren Repro-Schritten und präzisen Beschreibungen einreichen.

Deployment (Kurzleitfaden)

Produktivbetrieb: Kein Development-Modus, saubere Umgebungsvariablen

WSGI-Server: z. B. gunicorn oder uwsgi

Reverse Proxy: z. B. Nginx vor den WSGI-Server

Statische Dateien: Möglichst direkt über den Webserver ausliefern

Prozess-Management: systemd, Supervisor oder Container-Orchestrierung

Beispiel (gunicorn, vereinfacht):

pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 "app:app"

Troubleshooting

The virtual environment was not created successfully because ensurepip is not available
→ Auf Ubuntu/Debian fehlt oft das venv-Paket:

sudo apt update
sudo apt install -y python3.12-venv
rm -rf .venv
/usr/bin/python3.12 -m venv .venv
source .venv/bin/activate


ModuleNotFoundError: No module named '…'
→ Virtuelle Umgebung aktivieren und Abhängigkeiten neu installieren:

source .venv/bin/activate
pip install -r requirements.txt


Port 5000 belegt

flask run -p 5050


Native Build-Fehler (z. B. fehlender Compiler)

sudo apt install -y build-essential python3.12-dev

Support & Individuelle Erweiterungen

Diese Software wird unter der MIT-Lizenz bereitgestellt (siehe unten).
Individuelle Erweiterungen, Integrationen oder Funktionsanpassungen bieten wir auf Wunsch kostenpflichtig an – einschließlich Konzeption, Umsetzung, Tests und Deployment-Begleitung.
Für ein Angebot bitte mit einer kurzen Anforderungsskizze und ggf. Beispiel-Workflows anfragen.
