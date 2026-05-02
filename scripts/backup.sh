#!/bin/sh
# Automatic backup script for PostgreSQL

set -e

BACKUP_DIR="/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/inventoryapp_${TIMESTAMP}.sql.gz"
KEEP_DAYS=30

echo "🔄 Starting database backup..."
echo "📅 Timestamp: ${TIMESTAMP}"

# Create backup directory if not exists
mkdir -p ${BACKUP_DIR}

# Backup database
pg_dump -h db -U ${POSTGRES_USER} ${POSTGRES_DB} | gzip > ${BACKUP_FILE}

if [ -f ${BACKUP_FILE} ]; then
    BACKUP_SIZE=$(du -h ${BACKUP_FILE} | cut -f1)
    echo "✅ Backup completed: ${BACKUP_FILE} (${BACKUP_SIZE})"
else
    echo "❌ Backup failed!"
    exit 1
fi

# Cleanup old backups
echo "🧹 Cleaning up backups older than ${KEEP_DAYS} days..."
find ${BACKUP_DIR} -name "inventoryapp_*.sql.gz" -type f -mtime +${KEEP_DAYS} -delete

BACKUP_COUNT=$(find ${BACKUP_DIR} -name "inventoryapp_*.sql.gz" -type f | wc -l)
echo "📦 Total backups: ${BACKUP_COUNT}"

echo "✅ Backup process completed!"
