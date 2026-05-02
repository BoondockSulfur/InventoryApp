# InventoryApp v2.3.0

🚀 **Production-Ready Enterprise Inventory Management System** with GraphQL API, Real-Time Updates, Advanced Analytics, Multi-Language Support, and Integration Marketplace!

![Version](https://img.shields.io/badge/version-2.3.0-blue)
![Python](https://img.shields.io/badge/python-3.12+-blue)
![Flask](https://img.shields.io/badge/flask-2.3+-green)
![Docker](https://img.shields.io/badge/docker-ready-blue)
![GraphQL](https://img.shields.io/badge/GraphQL-ready-E10098)
![WebSocket](https://img.shields.io/badge/WebSocket-enabled-orange)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🎉 What's New in v2.3.0 - Full Roadmap Implementation!

### 🌍 Multi-Language Support (i18n)
- **Flask-Babel** integration for internationalization
- German and English translations included
- User-specific language preferences
- Easy to add more languages

### 📊 Advanced Analytics & Charts
- **Interactive Plotly charts** for inventory insights
- Inventory overview by category
- Loan timeline tracking
- Item status distribution (pie charts)
- Location heatmaps
- Overdue loans visualization

### ⚡ WebSocket Real-Time Updates
- **Live inventory updates** across all clients
- Real-time loan notifications
- Item status changes broadcast instantly
- User activity monitoring
- Event-driven architecture

### 🔌 GraphQL API
- **Flexible query language** for inventory data
- GraphiQL IDE included at `/graphql`
- Queries for items, loans, users, categories
- Mutations for create/update/delete operations
- Optimized data fetching

### 📄 Advanced Reporting Engine
- **Multi-format reports**: CSV, Excel, PDF
- Inventory reports with filters
- Loan activity reports
- Custom date ranges
- Professional Excel formatting with openpyxl
- PDF reports with WeasyPrint

### 🔗 Integration Marketplace
- **Plugin architecture** for third-party integrations
- **Webhook integration** with HMAC signatures
- **Slack notifications** for inventory events
- **Microsoft Teams** integration
- **Email notifications** for custom events
- Extensible plugin system

### 📱 Mobile API Ready
- RESTful API for mobile apps
- Complete API documentation in `MOBILE_APP_SPEC.md`
- React Native app specification included
- Barcode scanning support
- Offline mode ready

### 🌐 Kubernetes Deployment
- Production-ready K8s manifests
- 3-replica deployment with auto-scaling
- Service, ConfigMap, Ingress configurations
- TLS/SSL support with cert-manager
- Complete deployment guide

## 🎉 What's New in v2.1.0

### 🔄 Web-Based System Updates
- **One-Click Updates** from Admin Settings
- Automatic update checking from GitHub
- Live update progress tracking
- Automatic backup creation before updates
- Docker container auto-restart
- Changelog display for available updates

### 🔐 Advanced Authentication
- **OAuth Support**: Google, Microsoft, GitHub
- **SAML SSO** for enterprise environments
- Auto-registration for OAuth/SAML users
- Configurable default roles

### 🏢 Multi-Tenancy
- Multi-company support
- Company-specific branding and settings
- Data isolation between organizations
- Migration support for existing data

### 👥 Teams & Groups
- User groups with permissions
- Team management system
- Group-based access control
- Team-specific item assignments

[See full CHANGELOG](CHANGELOG.md)

---

## 🌟 Key Features

### 📦 Core Inventory Management
- Item creation, editing, deletion with rich details
- QR code and barcode generation
- RFID support for automated tracking
- Image uploads with auto-compression
- Bulk import/export (CSV, Excel)
- Advanced search with filters

### 🔄 Loan & Reservation System
- Loan tracking with due dates
- Reservation system with calendar view
- Approval workflow for sensitive items
- Overdue notifications
- Contract generation (PDF)
- Return management

### 🎫 Professional Ticket System
- Support ticket creation
- Comment functionality
- Status tracking
- Assignment to users
- Priority levels
- Toggle module on/off

### 💰 Budget & Analytics
- Budget tracking and monitoring
- Item value tracking
- Depreciation calculations
- Analytics dashboard
- Excel/PDF export
- Cost analysis

### 🔧 Maintenance Management
- Maintenance scheduling
- Automatic reminders
- Maintenance history
- Defect reporting
- Repair tracking
- Service documentation

### 🔐 Security & Access Control
- Role-based access control (RBAC)
- Granular permissions system
- Two-factor authentication (2FA)
- LDAP/Active Directory integration
- OAuth & SAML SSO
- Audit logging
- Session management

### 📍 Location Management
- Hierarchical location structure
- Floor plan uploads
- QR code for locations
- Location-based search
- Move history

### 📊 Reporting & Export
- iCal integration (Google Calendar, Outlook)
- Excel/CSV export
- PDF reports
- Custom filters
- Saved searches
- Audit reports

### 🔔 Notifications
- Email notifications
- Slack/Teams webhooks
- Push notifications
- Digest emails
- Customizable triggers

### 🎨 User Experience
- Dark mode support (Light/Dark/Auto)
- Responsive design (Mobile, Tablet, Desktop)
- PWA support (installable as app)
- Drag & drop file uploads
- Real-time updates
- Multi-language ready

---

## 🏗️ Architecture

### Production Docker Stack

```
┌─────────────────────────────────────────┐
│         Nginx (Reverse Proxy)           │
│            Port: 5500                   │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│      Flask App (Gunicorn)               │
│      7 Workers + Health Checks          │
└──────┬───────────────┬──────────────────┘
       │               │
       ▼               ▼
┌──────────────┐  ┌──────────────┐
│ PostgreSQL   │  │    Redis     │
│   Port: 5432 │  │  Port: 6379  │
│   16.4       │  │     7        │
└──────────────┘  └──────────────┘
```

### Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| **Backend** | Python, Flask | 3.12+, 2.3+ |
| **Database** | PostgreSQL | 16.4 |
| **Cache** | Redis | 7 |
| **Web Server** | Nginx | Latest |
| **WSGI** | Gunicorn | 21.2.0 |
| **ORM** | SQLAlchemy | 2.0+ |
| **Frontend** | Bootstrap, Jinja2 | 5.3.3 |
| **Auth** | Flask-Login, OAuth, SAML | Latest |
| **Container** | Docker, Docker Compose | Latest |
| **Testing** | pytest, pytest-cov | Latest |

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose installed
- Git
- (Optional) Python 3.12+ for local development

### Production Deployment (Recommended)

```bash
# 1. Clone repository
git clone https://github.com/BoondockSulfur/InventoryApp.git
cd InventoryApp

# 2. Configure environment
cp .env.production.example .env.production
# Edit .env.production and set required variables

# 3. Start all services
docker-compose -f docker-compose.production.yml up -d

# 4. Create admin user
docker-compose -f docker-compose.production.yml exec web python setup_admin.py

# 5. Access application
# http://localhost:5500
```

### Local Development

```bash
# 1. Clone repository
git clone https://github.com/BoondockSulfur/InventoryApp.git
cd InventoryApp

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env and set SECRET_KEY

# 5. Run application
python app.py

# 6. Access at http://localhost:5000
```

---

## 🔧 Configuration

### Environment Variables

#### Required Variables (.env.production)

```env
# Flask Core
SECRET_KEY=your-very-secret-random-key-here

# PostgreSQL Database
DATABASE_URL=postgresql://inventoryapp:yourpassword@db:5432/inventoryapp

# Redis Cache
REDIS_URL=redis://redis:6379/0

# Security
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
```

#### Optional Variables

```env
# Email Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
ADMIN_EMAIL=admin@example.com

# OAuth (Google)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# OAuth (Microsoft)
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret

# OAuth (GitHub)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# SAML SSO
SAML_METADATA_URL=https://your-idp.com/metadata
SAML_ENTITY_ID=https://your-domain.com
SAML_ACS_URL=https://your-domain.com/saml/acs

# Dell Warranty Integration
DELL_CLIENT_ID=your-dell-client-id
DELL_CLIENT_SECRET=your-dell-client-secret

# Slack/Teams Webhooks
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/xxx
```

### Generate Secure Keys

```bash
# SECRET_KEY
python -c 'import secrets; print(secrets.token_hex(32))'

# Database Password
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

---

## 📋 Docker Services

### Service Overview

```bash
# View running services
docker-compose -f docker-compose.production.yml ps

# View logs
docker-compose -f docker-compose.production.yml logs -f

# Restart service
docker-compose -f docker-compose.production.yml restart web

# Stop all services
docker-compose -f docker-compose.production.yml down

# Rebuild and restart
docker-compose -f docker-compose.production.yml up -d --build
```

### Service Details

#### Web Application (Flask + Gunicorn)
- **Port**: 5000 (internal)
- **Workers**: 7
- **Restart Policy**: always
- **Health Check**: /health endpoint
- **Volumes**: Persistent uploads, logs, backups

#### PostgreSQL Database
- **Port**: 5432 (internal)
- **Version**: 16.4
- **Volume**: postgres_data (persistent)
- **Health Check**: pg_isready

#### Redis Cache
- **Port**: 6379 (internal)
- **Version**: 7
- **Volume**: redis_data (persistent)
- **Health Check**: redis-cli ping

#### Nginx Reverse Proxy
- **Port**: 5500 (external)
- **Function**: Load balancer, static file serving
- **Config**: Custom nginx.conf

---

## 🔐 Security Features

### Implemented Security Measures

- ✅ **Strong Password Requirements**: Min. 12 characters with complexity
- ✅ **Rate Limiting**: Protection against brute-force attacks
- ✅ **CSRF Protection**: Enabled for all forms
- ✅ **Secure Sessions**: HTTPOnly, SameSite cookies
- ✅ **Password Hashing**: Werkzeug with salt
- ✅ **Random Admin Passwords**: No default passwords
- ✅ **Two-Factor Authentication**: Optional 2FA support
- ✅ **OAuth/SAML**: Enterprise SSO integration
- ✅ **Audit Logging**: Complete action history
- ✅ **Role-Based Access Control**: Granular permissions
- ✅ **SQL Injection Protection**: Parameterized queries
- ✅ **XSS Protection**: Escaped template output

### Security Best Practices

1. **Change Default Credentials**
   ```bash
   docker-compose exec web python setup_admin.py
   ```

2. **Enable HTTPS** (Production)
   - Configure SSL certificates
   - Set `SESSION_COOKIE_SECURE=true`

3. **Regular Backups**
   ```bash
   # Database backup
   docker-compose exec db pg_dump -U inventoryapp inventoryapp > backup.sql

   # Restore
   docker-compose exec -T db psql -U inventoryapp inventoryapp < backup.sql
   ```

4. **Update System**
   - Use web-based update system in Admin Settings
   - Or manual: `python update.py`

5. **Monitor Logs**
   ```bash
   docker-compose logs -f web
   tail -f logs/error.log
   ```

---

## 🔄 System Updates

### Web-Based Updates (Recommended)

1. Login as Admin
2. Navigate to Admin Settings
3. Go to "System-Updates" tab
4. Click "Check for Updates"
5. Review changelog
6. Click "Install Update"
7. System automatically:
   - Creates backup
   - Downloads updates
   - Updates dependencies
   - Restarts services

### Command-Line Updates

```bash
# Check for updates
python update.py --check

# Apply updates
python update.py

# Without auto-restart
python update.py --no-restart
```

### Manual Updates

```bash
# 1. Backup
docker-compose exec db pg_dump -U inventoryapp inventoryapp > backup.sql

# 2. Pull latest code
git pull origin main

# 3. Rebuild containers
docker-compose -f docker-compose.production.yml up -d --build

# 4. Run migrations (if any)
docker-compose exec web python -c "from app import db; db.create_all()"
```

---

## 🧪 Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=app --cov-report=html

# Specific test file
pytest tests/test_models.py

# Verbose output
pytest -v -s

# Run in Docker
docker-compose exec web pytest
```

Coverage report is generated in `htmlcov/index.html`.

---

## 📁 Project Structure

```
InventoryApp/
├── app.py                          # Main application
├── config.py                       # Configuration classes
├── requirements.txt                # Python dependencies
├── update.py                       # Update script
├── setup_admin.py                  # Admin setup script
│
├── docker-compose.production.yml   # Production Docker setup
├── docker-compose.yml              # Development Docker setup
├── Dockerfile.production           # Production Dockerfile
├── Dockerfile                      # Development Dockerfile
├── docker-entrypoint.sh            # Container startup script
│
├── nginx/                          # Nginx configuration
│   ├── nginx.conf
│   └── conf.d/app.conf
│
├── static/                         # Static files
│   ├── css/
│   ├── js/
│   ├── img/
│   └── uploads/                    # User uploads
│
├── templates/                      # Jinja2 templates
│   ├── base.html
│   ├── dashboard.html
│   ├── items/
│   ├── tickets/
│   ├── analytics/
│   ├── budget/
│   └── errors/
│
├── migrations/                     # Database migrations
│   └── *.sql
│
├── tests/                          # Test suite
│   ├── conftest.py
│   ├── test_models.py
│   ├── test_routes.py
│   └── test_security.py
│
├── logs/                           # Application logs
├── backups/                        # Automatic backups
│
├── CHANGELOG.md                    # Version history
├── UPDATE_GUIDE.md                 # Update documentation
├── GITHUB_SETUP.md                 # GitHub deployment guide
├── DOCKER_DEPLOYMENT.md            # Docker deployment guide
├── FEATURES_V2.md                  # Feature documentation
└── README.md                       # This file
```

---

## 👥 User Roles & Permissions

| Role | Description | Permissions |
|------|-------------|-------------|
| **Admin** | Full system access | All features, user management, system settings |
| **Manager** | Management staff | Item management, loans, tickets, reports |
| **Employee** | Standard user | View items, own tickets, reservations |
| **Customer** | External user | Own loans, ticket creation, view assigned items |

### Granular Permissions

- `manage_items` - Create, edit, delete items
- `manage_users` - User administration
- `manage_roles` - Role and permission management
- `view_analytics` - Access analytics dashboard
- `manage_budgets` - Budget administration
- `approve_requests` - Approve loan requests
- `manage_locations` - Location administration
- And many more...

---

## 🚨 Troubleshooting

### Common Issues

#### 1. Container won't start
```bash
# Check logs
docker-compose logs web

# Verify environment variables
docker-compose config

# Restart services
docker-compose restart
```

#### 2. Database connection errors
```bash
# Check PostgreSQL status
docker-compose exec db pg_isready

# Verify credentials in .env.production
cat .env.production | grep DATABASE_URL

# Restart database
docker-compose restart db
```

#### 3. Nginx 502 Bad Gateway
```bash
# Check web service health
docker-compose exec web curl http://localhost:5000/health

# View web logs
docker-compose logs web

# Restart web service
docker-compose restart web
```

#### 4. Permission denied errors
```bash
# Fix file permissions
chmod +x docker-entrypoint.sh
chown -R 1000:1000 static/uploads logs backups

# In Docker
docker-compose exec web chown -R appuser:appuser /app
```

#### 5. Port already in use
```bash
# Find process using port
sudo lsof -i :5500  # or netstat -tulpn | grep 5500

# Change port in docker-compose.production.yml
# nginx: ports: - "5501:80"
```

---

## 📊 Performance Optimization

### Database

```sql
-- Regular maintenance
VACUUM ANALYZE;
REINDEX DATABASE inventoryapp;

-- Check slow queries
SELECT * FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;
```

### Redis Caching

```bash
# Monitor Redis
docker-compose exec redis redis-cli INFO stats

# Clear cache
docker-compose exec redis redis-cli FLUSHDB
```

### Application Tuning

1. **Gunicorn Workers**
   - Formula: (2 x CPU cores) + 1
   - Adjust in `gunicorn_config.py`

2. **PostgreSQL Connection Pool**
   - Configure in `DATABASE_URL`
   - Default: pool_size=10

3. **Nginx Caching**
   - Static files cached for 30 days
   - Gzip compression enabled

---

## 🔗 API Documentation

For RESTful API usage, see [API.md](API.md)

Basic API endpoints:

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/items` | List all items | Yes |
| GET | `/api/items/<id>` | Get item details | Yes |
| POST | `/api/items` | Create item | Admin |
| PUT | `/api/items/<id>` | Update item | Admin |
| DELETE | `/api/items/<id>` | Delete item | Admin |
| GET | `/api/users` | List users | Admin |
| GET | `/health` | Health check | No |

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for new features
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guide
- Write docstrings for all functions
- Add tests for new features
- Update documentation
- Keep commits atomic and well-described

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Credits

Developed by **BoondockSulfur**
Powered by open-source technologies

### Special Thanks

- Flask & SQLAlchemy teams
- PostgreSQL & Redis communities
- Bootstrap team
- All contributors

---

## 📞 Support

- **Documentation**: This README, UPDATE_GUIDE.md, DOCKER_DEPLOYMENT.md
- **Issues**: [GitHub Issues](https://github.com/BoondockSulfur/InventoryApp/issues)
- **Discussions**: [GitHub Discussions](https://github.com/BoondockSulfur/InventoryApp/discussions)

---

## 🗺️ Roadmap

### ✅ Completed in v2.3.0

- [x] **GraphQL API** - Complete with GraphiQL IDE at `/graphql`
- [x] **WebSocket Real-Time Updates** - Live inventory updates with SocketIO
- [x] **Advanced Analytics & Charts** - Interactive Plotly visualizations
- [x] **Mobile API** - RESTful API ready for React Native app
- [x] **Kubernetes Deployment** - Production-ready K8s manifests
- [x] **Multi-Language UI (i18n)** - German & English with Flask-Babel
- [x] **Advanced Reporting Engine** - CSV, Excel, PDF generation
- [x] **Integration Marketplace** - Webhook, Slack, Teams, Email plugins

### 🚀 Planned for v2.4.0

- [ ] Mobile App Implementation (React Native)
  - iOS & Android native apps
  - Offline mode with sync
  - Barcode scanning
  - Push notifications
- [ ] Advanced Search & Filters
  - Elasticsearch integration
  - Full-text search
  - Advanced filtering UI
- [ ] Audit Trail Enhancements
  - Detailed change history
  - Diff view for changes
  - Export audit logs
- [ ] Custom Workflows
  - Approval workflows for loans
  - Custom status transitions
  - Notification rules
- [ ] AI-Powered Features
  - Smart categorization
  - Predictive maintenance alerts
  - Usage pattern analysis

### 💡 Future Considerations (v3.0+)

- [ ] Microservices Architecture
- [ ] Multi-tenancy SaaS Mode
- [ ] Blockchain for audit trail
- [ ] IoT Device Integration (RFID readers, sensors)
- [ ] Advanced BI & Data Warehouse
- [ ] White-label customization

### ✅ Previously Completed

- [x] Web-based update system
- [x] OAuth/SAML authentication
- [x] Multi-company support
- [x] Groups & teams

---

**🚀 InventoryApp - Enterprise Inventory Management Made Simple**

For detailed deployment instructions, see [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md)

For update procedures, see [UPDATE_GUIDE.md](UPDATE_GUIDE.md)
