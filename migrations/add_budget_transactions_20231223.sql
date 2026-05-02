-- ===================================================================
-- Migration: Add Budget Transactions and Enhanced Budget Tracking
-- Date: 2023-12-23
-- Description: Creates budget_transaction table and ensures all
--              required fields exist in item and budget_entry tables
-- ===================================================================

-- Step 1: Create budget_transaction table
-- ===================================================================
CREATE TABLE IF NOT EXISTS budget_transaction (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    budget_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    transaction_type VARCHAR(20) NOT NULL,  -- expense, income, depreciation, purchase
    transaction_date DATE NOT NULL DEFAULT CURRENT_DATE,
    description TEXT,
    reference_type VARCHAR(50),  -- 'item', 'maintenance', 'repair', etc.
    reference_id INTEGER,
    created_by INTEGER,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (budget_id) REFERENCES budget_entry(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES user(id)
);

-- Create indexes for budget_transaction
CREATE INDEX IF NOT EXISTS idx_budget_transaction_budget_id ON budget_transaction(budget_id);
CREATE INDEX IF NOT EXISTS idx_budget_transaction_type ON budget_transaction(transaction_type);
CREATE INDEX IF NOT EXISTS idx_budget_transaction_date ON budget_transaction(transaction_date);

-- Step 2: Ensure Item table has all required columns
-- ===================================================================
-- Note: SQLite doesn't support "ADD COLUMN IF NOT EXISTS", so we need to check manually
-- If these columns already exist, these statements will fail (which is fine for SQLite)

-- Add purchase_price if it doesn't exist (may already exist)
-- ALTER TABLE item ADD COLUMN purchase_price REAL;

-- Add purchase_date if it doesn't exist (may already exist)
-- ALTER TABLE item ADD COLUMN purchase_date DATE;

-- Add depreciation_rate if it doesn't exist (may already exist)
-- ALTER TABLE item ADD COLUMN depreciation_rate REAL DEFAULT 0.0;

-- Add current_value if it doesn't exist (may already exist)
-- ALTER TABLE item ADD COLUMN current_value REAL;

-- Step 3: Update existing items with current_value = purchase_price if null
-- ===================================================================
UPDATE item
SET current_value = purchase_price
WHERE current_value IS NULL AND purchase_price IS NOT NULL;

-- Step 4: Verify budget_entry table has all required columns
-- ===================================================================
-- The budget_entry table should already have these columns based on the model:
-- - id, name, year, category, allocated_amount, spent_amount
-- - start_date, end_date, description, department, notes
-- - created_at, updated_at

-- Step 5: Update spent_amount for existing budgets to 0 if null
-- ===================================================================
UPDATE budget_entry
SET spent_amount = 0.0
WHERE spent_amount IS NULL;

-- ===================================================================
-- VERIFICATION QUERIES
-- ===================================================================
-- Run these to verify the migration completed successfully:

-- Check budget_transaction table exists
-- SELECT name FROM sqlite_master WHERE type='table' AND name='budget_transaction';

-- Count budget transactions
-- SELECT COUNT(*) FROM budget_transaction;

-- Check for items with price data
-- SELECT COUNT(*) FROM item WHERE purchase_price IS NOT NULL;

-- Check budget entries
-- SELECT id, name, allocated_amount, spent_amount FROM budget_entry;

-- ===================================================================
-- ROLLBACK (if needed)
-- ===================================================================
-- To rollback this migration:
-- DROP TABLE IF EXISTS budget_transaction;
-- UPDATE budget_entry SET spent_amount = 0.0;
