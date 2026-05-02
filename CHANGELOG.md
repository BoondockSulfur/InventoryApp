# Changelog

Alle wichtigen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/).

## [2.3.0] - 2025-12-21

### 🚀 Major Release - Full Roadmap Feature Implementation

This is a comprehensive release implementing **all** features from the v2.2.0 roadmap, transforming infrastructure foundations into fully functional, production-ready features.

### Features - Fully Implemented

#### 🌍 Multi-Language Support (i18n)
- **ADDED:** Complete Flask-Babel integration with language selection
- **ADDED:** German translations (translations/de/LC_MESSAGES/messages.po)
- **ADDED:** English translations (translations/en/LC_MESSAGES/messages.po)
- **ADDED:** User-specific language preferences stored in database
- **ADDED:** Language switcher route `/set-language/<lang>`
- **ADDED:** Automatic locale detection from browser
- **ADDED:** Session-based language persistence

#### 📊 Advanced Analytics & Interactive Charts
- **ADDED:** Complete analytics module (analytics.py)
- **ADDED:** Inventory overview chart by category (Plotly bar chart)
- **ADDED:** Loan timeline chart (30-day activity line chart)
- **ADDED:** Item status pie chart (Available/Borrowed/Defective)
- **ADDED:** Location distribution heatmap
- **ADDED:** Overdue loans chart by user
- **ADDED:** Dashboard analytics page at `/analytics`
- **ADDED:** JSON API endpoint `/analytics/api/charts`
- **ADDED:** Individual chart endpoints `/analytics/api/chart/<type>`

#### ⚡ WebSocket Real-Time Updates
- **ADDED:** Complete SocketIO integration (socketio_events.py)
- **ADDED:** Connection/disconnection event handlers
- **ADDED:** Room-based targeted updates (join/leave rooms)
- **ADDED:** Item created/updated/deleted broadcasts
- **ADDED:** Loan created/returned broadcasts
- **ADDED:** Overdue loan notifications
- **ADDED:** User activity monitoring
- **ADDED:** Redis message queue for scalability
- **ADDED:** Helper functions for easy event broadcasting

#### 🔌 GraphQL API
- **ADDED:** Complete GraphQL schema (graphql_schema.py)
- **ADDED:** SQLAlchemy-based object types for Item, User, Loan, Category, Location, Company, Team
- **ADDED:** Comprehensive Query type with resolvers:
  - Items (all, by ID, by category, by location, available, borrowed, defective)
  - Users (all, by ID)
  - Loans (all, active, overdue, by ID)
  - Categories and Locations
  - Companies and Teams
- **ADDED:** Mutation types:
  - CreateItem, UpdateItem, DeleteItem
  - CreateLoan, ReturnLoan
- **ADDED:** GraphiQL IDE at `/graphql` for interactive queries
- **ADDED:** Relay connection support for pagination

#### 📄 Advanced Reporting Engine
- **ADDED:** Complete reporting module (reporting.py)
- **ADDED:** ReportGenerator class with multiple format support
- **ADDED:** CSV report generation for inventory and loans
- **ADDED:** Excel report generation with professional formatting:
  - Styled headers with colors
  - Auto-adjusted column widths
  - Cell borders and alignment
- **ADDED:** PDF report generation with WeasyPrint:
  - Professional HTML templates
  - Table formatting
  - Header/footer support
- **ADDED:** Report filtering (by category, location, status, date range)
- **ADDED:** Report routes:
  - `/reports/generate` - Report generation page
  - `/reports/inventory?format=csv|excel|pdf` - Inventory reports
  - `/reports/loans?format=csv|excel` - Loan reports

#### 🔗 Integration Marketplace
- **ADDED:** Complete integration system (integrations.py)
- **ADDED:** IntegrationPlugin base class for extensibility
- **ADDED:** WebhookIntegration with HMAC signature support
- **ADDED:** SlackIntegration for Slack notifications
- **ADDED:** MSTeamsIntegration for Microsoft Teams
- **ADDED:** EmailIntegration for email notifications
- **ADDED:** IntegrationManager for plugin lifecycle management
- **ADDED:** Event system (item.created, item.updated, loan.created, etc.)
- **ADDED:** Database-driven integration configuration
- **ADDED:** Easy plugin addition/removal
- **ADDED:** Error handling and logging

#### 📱 Mobile API
- **ADDED:** RESTful API routes (api_routes.py)
- **ADDED:** Mobile API endpoints:
  - `GET /api/items` - List items with pagination and search
  - `GET /api/items/<id>` - Item details
  - `GET /api/items/barcode/<barcode>` - Lookup by barcode
  - `GET /api/loans/active` - Active loans
  - `GET /api/loans/overdue` - Overdue loans
  - `GET /api/categories` - All categories
  - `GET /api/locations` - All locations
  - `GET /api/auth/me` - Current user info
- **ADDED:** Model serialization (to_dict() methods)
- **ADDED:** Mobile App Specification (MOBILE_APP_SPEC.md)
- **ADDED:** React Native app architecture documentation
- **ADDED:** Complete API documentation for mobile developers

### Infrastructure & Code Quality

- **ADDED:** Modular architecture with separate files:
  - graphql_schema.py - GraphQL schema definitions
  - socketio_events.py - WebSocket event handlers
  - analytics.py - Analytics chart generation
  - reporting.py - Report generation engine
  - integrations.py - Integration marketplace system
  - api_routes.py - API routes and endpoints
- **ADDED:** Graceful degradation when optional dependencies unavailable
- **ADDED:** Comprehensive error handling and logging
- **ADDED:** Helper functions for integration/WebSocket triggers
- **ADDED:** SocketIO server support in main application runner

### Dependencies Added

- **ADDED:** graphene-sqlalchemy==3.0.0 - GraphQL SQLAlchemy integration
- **ADDED:** pandas==2.1.4 - Data manipulation for analytics

### Documentation

- **ADDED:** MOBILE_APP_SPEC.md - Complete mobile app specification
  - React Native architecture
  - API endpoint documentation
  - Offline mode strategy
  - Push notification setup
  - Build & release instructions
- **UPDATED:** ROADMAP_IMPLEMENTATION.md - Updated with implementation status
- **UPDATED:** README.md - Version 2.3.0 with feature showcase
- **UPDATED:** CHANGELOG.md - This comprehensive changelog

### Version Management

- Version bumped from 2.2.0 to 2.3.0
- All roadmap features **fully implemented** and production-ready
- Complete test coverage for new features

### Notes

This release represents the **full implementation** of all v2.2.0 roadmap features. Unlike v2.2.0 which provided infrastructure, v2.3.0 delivers complete, working implementations:

- ✅ Multi-language UI is **fully functional**
- ✅ Analytics charts are **interactive and live**
- ✅ WebSocket updates are **real-time**
- ✅ GraphQL API is **queryable with GraphiQL**
- ✅ Reports generate in **CSV, Excel, and PDF**
- ✅ Integrations can **send webhooks, Slack, Teams messages**
- ✅ Mobile API is **documented and ready for React Native**

## [2.2.0] - 2025-12-21

### Major Features - Roadmap Implementation (Foundation Ready)

- **ADDED:** Multi-Language Support (i18n) Infrastructure
  - Flask-Babel 4.0.0 integration
  - Translation extraction configuration (babel.cfg)
  - Ready for locale implementation (German, English, etc.)
  - Toggle switch in Admin Settings (to be activated)

- **ADDED:** Advanced Analytics & Charts Foundation
  - Plotly 5.18.0 for interactive visualizations
  - Infrastructure for inventory analytics
  - Chart types: Bar, Line, Pie, Heatmap
  - Ready for dashboard integration

- **ADDED:** WebSocket Real-Time Updates Infrastructure
  - Flask-SocketIO 5.3.5 & python-socketio 5.10.0
  - Foundation for live inventory updates
  - Event-driven architecture prepared
  - Toggle switch in Admin Settings (to be activated)

- **ADDED:** GraphQL API Foundation
  - graphene 3.3 & Flask-GraphQL 2.0.1
  - Infrastructure for flexible API queries
  - Schema definition framework ready
  - Alternative to REST API (to be implemented)

- **ADDED:** Advanced Reporting Engine Foundation
  - Multi-format export capability (PDF, Excel, CSV)
  - Custom report builder infrastructure
  - Scheduled reporting framework
  - Template system prepared

- **ADDED:** Kubernetes Deployment Support
  - Complete K8s manifests in k8s/ directory
  - Deployment with 3 replicas and rolling updates
  - Service, ConfigMap, and Ingress configurations
  - Auto-scaling ready with resource limits
  - TLS/SSL support with cert-manager
  - Comprehensive deployment guide (k8s/README.md)

- **ADDED:** Integration Marketplace Foundation
  - Plugin architecture framework
  - Third-party integration support structure
  - Webhook system foundation
  - API connector templates

### Documentation

- **ADDED:** ROADMAP_IMPLEMENTATION.md - Complete feature implementation guide
  - Status of all roadmap features
  - Implementation instructions for each feature
  - Usage examples and code snippets
  - Known limitations and future enhancements

- **ADDED:** k8s/README.md - Kubernetes deployment guide
  - Architecture overview
  - Quick start deployment steps
  - Configuration and scaling instructions
  - Security best practices
  - Troubleshooting guide

### Dependencies

- **ADDED:** Flask-Babel==4.0.0 - Multi-language support
- **ADDED:** Flask-SocketIO==5.3.5 - WebSocket support
- **ADDED:** python-socketio==5.10.0 - WebSocket client/server
- **ADDED:** graphene==3.3 - GraphQL schema framework
- **ADDED:** Flask-GraphQL==2.0.1 - GraphQL API integration
- **ADDED:** plotly==5.18.0 - Advanced charts and analytics

### Infrastructure

- **ADDED:** Kubernetes manifests for production deployment
  - deployment.yaml - Main application with 3 replicas
  - service.yaml - ClusterIP service on port 80
  - configmap.yaml - Environment configuration
  - ingress.yaml - HTTPS ingress with Let's Encrypt

### Version Management

- Version bumped from 2.1.0 to 2.2.0
- All roadmap features infrastructure implemented
- Foundation ready for feature activation

### Notes

This release focuses on **infrastructure and foundation** for all roadmap features. Features include toggle switches in Admin Settings and can be activated/completed as needed. See ROADMAP_IMPLEMENTATION.md for detailed implementation instructions.

## [2.1.0] - 2025-12-21

### Major Features
- **ADDED:** Web-based System Update Feature in Admin Settings
  - Automatic update checking from GitHub
  - One-click update installation
  - Automatic backup creation before updates
  - Live update progress tracking
  - Automatic Docker container restart
  - Changelog display for available updates
- **ADDED:** Complete OAuth & SAML Authentication System
  - Google OAuth login support
  - Microsoft OAuth login support
  - GitHub OAuth login support
  - SAML SSO for enterprise environments
  - Auto-registration for OAuth/SAML users
- **ADDED:** Multi-Company / Multi-Tenant Support
  - Company model with branding options
  - Data isolation between organizations
  - Company-specific settings
  - Migration support for existing data
- **ADDED:** Professional Groups & Teams System
  - User groups with many-to-many relationships
  - Group-based permissions
  - Team management with roles
  - Team-specific item assignments

### Enhancements
- **IMPROVED:** Permissions UI with search functionality
- **IMPROVED:** Bulk import with professional column mapping
- **IMPROVED:** Ticket system made toggleable via module settings
- **IMPROVED:** Budget overview with better error handling
- **ADDED:** Professional update.py script for command-line updates
- **ADDED:** Comprehensive update documentation (UPDATE_GUIDE.md, GITHUB_SETUP.md)
- **ADDED:** Clean Git history with professional commit structure

### Documentation
- **ADDED:** UPDATE_GUIDE.md - Complete update system documentation
- **ADDED:** GITHUB_SETUP.md - GitHub deployment instructions
- **UPDATED:** FEATURES_V2.md - All new features documented
- **UPDATED:** README.md - Updated with new version info

### Version Management
- Version bumped from 2.0.0 to 2.1.0
- Clean Git repository with fresh commit history
- Production-ready deployment configuration

## [2.0.0] - 2025-12-20

### Complete System Overhaul
- Initial production release with comprehensive features
- Docker-based deployment
- PostgreSQL database
- Redis caching
- Complete role-based access control

## [1.0.1] - 2025-12-19

### Sicherheit (CRITICAL)
- **FIXED:** Default-Admin mit Passwort "admin" durch zufällig generiertes sicheres Passwort ersetzt (app.py:1206-1226)
- **ADDED:** Rate Limiting für Login-Route (5 Versuche/Minute) zur Verhinderung von Brute-Force-Angriffen (app.py:483)
- **ADDED:** Rate Limiting für Password-Reset-Routes (3 Versuche/Stunde) (app.py:500, 514)
- **ADDED:** Session-Invalidation nach Passwort-Reset (app.py:516-517)
- **ADDED:** Sichere Session-Konfiguration (SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SAMESITE) (app.py:58-60)
- **IMPROVED:** Passwortanforderungen von 6 auf 12 Zeichen erhöht mit Komplexitätsprüfung (Groß-/Kleinbuchstaben, Zahlen, Sonderzeichen) (app.py:231-238, 246-253)
- **ADDED:** Config-Validierung für SECRET_KEY (app.py:49-51)

### Bugfixes (HIGH)
- **FIXED:** Duplicate relationship definition in Loan Model entfernt (app.py:167-169)
- **FIXED:** Bare except clause in verify_reset_token durch spezifische Exception-Handler ersetzt (app.py:146)
- **FIXED:** Template-Fehler: loan.borrower.name → loan.borrower.username (templates/item_detail.html:24)
- **FIXED:** Fehlerhafter Attributzugriff in check_overdue Funktion: bor.name → bor.username (app.py:434)

### Performance (MEDIUM)
- **FIXED:** N+1 Query-Problem in check_overdue durch Joins behoben (app.py:398-402)
- **FIXED:** Ineffiziente Query in items() Route durch Subquery ersetzt (app.py:596-597)
- **ADDED:** Pagination für Item-Liste (50 Items pro Seite) zur Verbesserung der Ladezeiten (app.py:602-607)
- **ADDED:** Pagination-UI im items.html Template (templates/items.html:190-227)

### Database Schema
- **ADDED:** Indizes für häufig abgefragte Felder:
  - User: username, email, role (app.py:142-145)
  - Item: name, serial, category, is_borrowed, defective (app.py:171-177)
  - Loan: item_id, borrower_id, loan_date, due_date, return_date (app.py:184-188)
  - AuditLog: user_id, endpoint, method, timestamp (app.py:217-221)
- **ADDED:** Timestamps (created_at, updated_at) für alle Models (app.py:147-148, 178-179, 189-190)
- **ADDED:** ON DELETE CASCADE für Foreign Keys in Loan Model (app.py:184-185)
- **CHANGED:** AuditLog.user_id nullable mit ON DELETE SET NULL (app.py:217)

### Error Handling
- **ADDED:** Error-Handler für 404, 403, 500, 429 (app.py:1274-1290)
- **ADDED:** Error-Templates (templates/errors/404.html, 403.html, 500.html, 429.html)
- **ADDED:** Try-catch-Blöcke für Mail-Versand in check_overdue mit Logging (app.py:410-439)
- **ADDED:** Logging für fehlgeschlagene und erfolgreiche Logins (app.py:491, 494)
- **ADDED:** Database-Rollback in 500-Error-Handler (app.py:1284)

### Dependencies
- **UPDATED:** Alle Dependencies mit Version-Pinning für bessere Stabilität (requirements.txt)
- **ADDED:** Flask-Limiter>=3.5.0,<4.0.0 für Rate Limiting
- **ADDED:** gunicorn>=21.2.0,<22.0.0 für Production-Deployment
- **ADDED:** Flask-Migrate>=4.0.0,<5.0.0 für Database-Migrationen
- **ADDED:** pytest>=7.4.0,<8.0.0, pytest-flask>=1.2.0,<2.0.0, pytest-cov>=4.1.0,<5.0.0 für Testing
- **ADDED:** Regexp Validator zu WTForms-Imports (app.py:31)

### Deployment & Configuration
- **ADDED:** Dockerfile für Container-Deployment
- **ADDED:** docker-compose.yml für einfaches Multi-Container-Setup
- **ADDED:** .dockerignore für optimierte Image-Größe
- **ADDED:** config.py mit separaten Konfigurationsklassen (Development, Production, Testing)
- **ADDED:** .env.example als Template für Umgebungsvariablen
- **ADDED:** Healthcheck in docker-compose.yml

### Testing
- **ADDED:** Pytest-Setup mit pytest.ini
- **ADDED:** Test-Suite in tests/ Verzeichnis:
  - conftest.py mit Fixtures für App, DB, Users, Items
  - test_models.py für Model-Tests (User, Item, Loan)
  - test_routes.py für Route-Tests (Auth, Items, Dashboard, Errors)
  - test_security.py für Sicherheitstests (Password, CSRF, Rate Limiting, Access Control)
- **ADDED:** Code-Coverage-Konfiguration

### Logging
- **IMPROVED:** Admin-Benachrichtigungen werden jetzt an alle Admins gleichzeitig gesendet (app.py:426-439)
- **ADDED:** Info-Logging für erfolgreiche Operationen (app.py:421, 437)
- **ADDED:** Error-Logging für fehlgeschlagene Mail-Operationen (app.py:423, 439)

### Documentation
- **REWRITTEN:** README.md komplett überarbeitet mit:
  - Umfassende Feature-Liste
  - Detaillierte Installationsanleitung
  - Docker-Deployment-Guide
  - Sicherheitshinweise
  - Testing-Anleitung
  - Troubleshooting-Sektion
  - API-Endpoints-Übersicht
  - Changelog
  - Roadmap
- **ADDED:** CHANGELOG.md (diese Datei)
- **ADDED:** Inline-Dokumentation für kritische Code-Abschnitte

### Code Quality
- **IMPROVED:** Imports organisiert und Regexp zu Validators hinzugefügt (app.py:31)
- **IMPROVED:** Konsistente Verwendung von Subqueries statt mehrfacher DB-Abfragen
- **IMPROVED:** Bessere Fehlerbehandlung mit spezifischen Exceptions
- **IMPROVED:** Konsistente Verwendung von __tablename__ in Models (app.py:182, 215)

## [1.0.0] - Original Release

### Initial Features
- Bestandsverwaltung (Items)
- Leihsystem (Loans)
- Ticketsystem
- Benutzerverwaltung mit Rollen
- Dell Warranty Integration
- Barcode-Druck
- PDF-Vertragsgenerierung
- E-Mail-Benachrichtigungen
- Audit-Logging

---

## Breaking Changes

### Von 1.0.0 zu 1.0.1

#### Database Schema
Die folgenden Felder wurden hinzugefügt und erfordern eine Migration:
- `created_at` und `updated_at` in User, Item, Loan
- Indizes für Performance-Optimierung

**Migration erforderlich:**
```bash
pip install Flask-Migrate
flask db init
flask db migrate -m "Add timestamps and indexes"
flask db upgrade
```

#### Passwort-Anforderungen
Passwörter müssen jetzt mindestens 12 Zeichen lang sein und Groß-/Kleinbuchstaben, Zahlen und Sonderzeichen enthalten.

**Aktion erforderlich:**
- Bestehende Nutzer müssen ihr Passwort beim nächsten Login aktualisieren
- Admin-Passwort wird beim ersten Start automatisch mit einem zufälligen Passwort erstellt

#### Environment Variables
`SECRET_KEY` ist jetzt zwingend erforderlich und wird validiert.

**Aktion erforderlich:**
```bash
# Generieren Sie einen SECRET_KEY:
python -c 'import secrets; print(secrets.token_hex(32))'
# Fügen Sie diesen zu .env hinzu
```

---

## Security Advisory

### Kritische Sicherheitsupdates in 1.0.1

Wenn Sie Version 1.0.0 verwenden, aktualisieren Sie **sofort** auf 1.0.1:

1. **Default-Admin-Credentials:** Version 1.0.0 hatte admin/admin als Standard-Login
2. **Fehlende Rate-Limiting:** Login konnte unbegrenzt oft versucht werden
3. **Schwache Passwörter:** Nur 6 Zeichen waren erforderlich
4. **Session-Sicherheit:** Sessions wurden nach Passwort-Reset nicht invalidiert

---

## Upgrade-Pfad

### Von 1.0.0 zu 1.0.1

```bash
# 1. Backup erstellen
cp instance/inventory.db instance/inventory.db.backup

# 2. Code aktualisieren
git pull origin main

# 3. Dependencies aktualisieren
pip install -r requirements.txt

# 4. .env konfigurieren
cp .env.example .env
# SECRET_KEY setzen!

# 5. Database migrieren
pip install Flask-Migrate
flask db init
flask db migrate -m "Upgrade to 1.0.1"
flask db upgrade

# 6. Admin-Passwort ändern
# Beim ersten Start wird ein neues zufälliges Passwort generiert
python app.py
# Notieren Sie das Passwort aus der Konsole
# Nach Login sofort ändern!

# 7. Tests ausführen
pytest
```

---

## Contributors

Danke an alle, die zu diesem Projekt beigetragen haben!

- BoondockSulfur - Initial work & Maintainer
- Community - Bug Reports & Feature Requests
