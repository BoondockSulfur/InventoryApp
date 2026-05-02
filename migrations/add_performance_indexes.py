#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Database Performance Index Migration
=====================================
Adds missing indexes on frequently queried columns to improve performance.

This script is idempotent - it checks if indexes exist before creating them,
so it's safe to run multiple times.

Run with: python migrations/add_performance_indexes.py
"""

import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load environment variables
load_dotenv()

# Import SQLAlchemy directly
from sqlalchemy import create_engine, inspect, Index, MetaData, Table
from sqlalchemy.exc import OperationalError, ProgrammingError

# Get database URL from environment
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///instance/inventory.db')


def index_exists(engine, table_name, index_name):
    """Check if an index exists on a table."""
    inspector = inspect(engine)
    existing_indexes = inspector.get_indexes(table_name)
    return any(idx['name'] == index_name for idx in existing_indexes)


def create_index_safe(engine, index_obj, table_name, description):
    """Safely create an index, checking if it exists first."""
    index_name = index_obj.name

    if index_exists(engine, table_name, index_name):
        print(f"  [SKIP] Index '{index_name}' already exists on {table_name}")
        return False

    try:
        index_obj.create(engine)
        print(f"  [OK] Created index '{index_name}' on {table_name} - {description}")
        return True
    except (OperationalError, ProgrammingError) as e:
        print(f"  [ERROR] Failed to create index '{index_name}': {e}")
        return False


def add_indexes():
    """Add all missing performance indexes."""
    print("\n" + "="*70)
    print("DATABASE PERFORMANCE INDEX MIGRATION")
    print("="*70 + "\n")

    indexes_added = 0
    indexes_skipped = 0
    indexes_failed = 0

    # Create engine
    engine = create_engine(DATABASE_URL)
    metadata = MetaData()
    metadata.reflect(bind=engine)

    print("Analyzing database structure...")
    print(f"Database: {engine.url}\n")

    # Get table objects
    item_table = metadata.tables.get('item')
    ticket_table = metadata.tables.get('ticket')
    maintenance_table = metadata.tables.get('maintenance')
    reservation_table = metadata.tables.get('reservation')

    # ===================================================================
    # ITEM TABLE INDEXES
    # ===================================================================
    print(">>> ITEM TABLE")
    print("-" * 70)

    if item_table is not None:
        # Note: serial, barcode, and rfid_tag_id should already have indexes
        # Let's verify they exist (skip if columns don't exist)
        item_indexes = []

        if 'serial' in item_table.c:
            item_indexes.append((Index('ix_item_serial_perf', item_table.c.serial), 'item', 'Fast serial number lookups'))
        if 'barcode' in item_table.c:
            item_indexes.append((Index('ix_item_barcode_perf', item_table.c.barcode), 'item', 'Fast barcode lookups'))
        if 'rfid_tag_id' in item_table.c:
            item_indexes.append((Index('ix_item_rfid_tag_id_perf', item_table.c.rfid_tag_id), 'item', 'Fast RFID tag lookups'))

        for idx, table, desc in item_indexes:
            if index_exists(engine, table, idx.name):
                print(f"  [OK] Index '{idx.name}' already exists")
                indexes_skipped += 1
            else:
                if create_index_safe(engine, idx, table, desc):
                    indexes_added += 1
                else:
                    indexes_failed += 1

        if not item_indexes:
            print("  [INFO] No relevant columns found for indexing")
    else:
        print("  [SKIP] Table 'item' not found")

    # ===================================================================
    # TICKET TABLE INDEXES
    # ===================================================================
    print("\n>>> TICKET TABLE")
    print("-" * 70)

    if ticket_table is not None:
        ticket_indexes = []

        if 'status' in ticket_table.c:
            ticket_indexes.append((Index('ix_ticket_status_perf', ticket_table.c.status), 'ticket', 'Filter tickets by status (open, closed, etc.)'))
        if 'priority' in ticket_table.c:
            ticket_indexes.append((Index('ix_ticket_priority_perf', ticket_table.c.priority), 'ticket', 'Filter tickets by priority (low, high, urgent)'))

        for idx, table, desc in ticket_indexes:
            if create_index_safe(engine, idx, table, desc):
                indexes_added += 1
            elif index_exists(engine, table, idx.name):
                indexes_skipped += 1
            else:
                indexes_failed += 1

        if not ticket_indexes:
            print("  [INFO] No relevant columns found for indexing")
    else:
        print("  [SKIP] Table 'ticket' not found")

    # ===================================================================
    # MAINTENANCE TABLE INDEXES
    # ===================================================================
    print("\n>>> MAINTENANCE TABLE")
    print("-" * 70)

    if maintenance_table is not None:
        maintenance_indexes = []

        if 'status' in maintenance_table.c:
            maintenance_indexes.append((Index('ix_maintenance_status_perf', maintenance_table.c.status), 'maintenance', 'Filter maintenance by status'))
        if 'scheduled_date' in maintenance_table.c:
            maintenance_indexes.append((Index('ix_maintenance_scheduled_date_perf', maintenance_table.c.scheduled_date), 'maintenance', 'Date range queries for scheduled maintenance'))

        for idx, table, desc in maintenance_indexes:
            if create_index_safe(engine, idx, table, desc):
                indexes_added += 1
            elif index_exists(engine, table, idx.name):
                indexes_skipped += 1
            else:
                indexes_failed += 1

        if not maintenance_indexes:
            print("  [INFO] No relevant columns found for indexing")
    else:
        print("  [SKIP] Table 'maintenance' not found")

    # ===================================================================
    # RESERVATION TABLE INDEXES
    # ===================================================================
    print("\n>>> RESERVATION TABLE")
    print("-" * 70)

    if reservation_table is not None:
        reservation_indexes = []

        if 'status' in reservation_table.c:
            reservation_indexes.append((Index('ix_reservation_status_perf', reservation_table.c.status), 'reservation', 'Filter reservations by status'))
        if 'start_date' in reservation_table.c:
            reservation_indexes.append((Index('ix_reservation_start_date_perf', reservation_table.c.start_date), 'reservation', 'Date range queries for reservation start'))
        if 'end_date' in reservation_table.c:
            reservation_indexes.append((Index('ix_reservation_end_date_perf', reservation_table.c.end_date), 'reservation', 'Date range queries for reservation end'))

        for idx, table, desc in reservation_indexes:
            if create_index_safe(engine, idx, table, desc):
                indexes_added += 1
            elif index_exists(engine, table, idx.name):
                indexes_skipped += 1
            else:
                indexes_failed += 1

        if not reservation_indexes:
            print("  [INFO] No relevant columns found for indexing")
    else:
        print("  [SKIP] Table 'reservation' not found")

    # ===================================================================
    # SUMMARY
    # ===================================================================
    print("\n" + "="*70)
    print("MIGRATION SUMMARY")
    print("="*70)
    print(f"  Indexes added:   {indexes_added}")
    print(f"  Indexes skipped: {indexes_skipped} (already existed)")
    print(f"  Indexes failed:  {indexes_failed}")
    print()

    if indexes_failed > 0:
        print("  [WARNING] Some indexes failed to create. Check errors above.")
        return False
    elif indexes_added > 0:
        print("  [SUCCESS] Migration completed successfully!")
        return True
    else:
        print("  [INFO] All indexes already exist. No changes needed.")
        return True


def main():
    """Main entry point."""
    try:
        success = add_indexes()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n[FATAL ERROR] Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
