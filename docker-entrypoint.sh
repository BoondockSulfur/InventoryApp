#!/bin/sh
set -e

echo "=========================================="
echo "  InventoryApp - Production Startup"
echo "=========================================="
echo ""

# Wait for PostgreSQL
echo "⏳ Waiting for PostgreSQL..."
until python -c "import socket; s = socket.socket(); s.connect(('db', 5432)); s.close()" 2>/dev/null; do
  sleep 1
done
echo "✅ PostgreSQL is ready!"

# Wait for Redis
echo "⏳ Waiting for Redis..."
until python -c "import socket; s = socket.socket(); s.connect(('redis', 6379)); s.close()" 2>/dev/null; do
  sleep 1
done
echo "✅ Redis is ready!"

# Run database setup
echo ""
echo "🔄 Initializing database..."
python - <<EOF
from app import app, db, setup
with app.app_context():
    setup()
print("✅ Database initialized!")
EOF

# Check if admin exists
echo ""
echo "👤 Checking admin account..."
python - <<EOF
from app import app, db, User
with app.app_context():
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        print("⚠️  WARNING: No admin account found!")
        print("   Run: docker-compose exec web python setup_admin.py")
    else:
        print(f"✅ Admin account found: {admin.username}")
EOF

echo ""
echo "=========================================="
echo "  🚀 Starting Application"
echo "=========================================="
echo ""

# Execute CMD
exec "$@"
