#!/usr/bin/env python3
"""
InventoryApp Update Script
Handles automatic updates from GitHub repository
"""

import os
import sys
import subprocess
import shutil
from datetime import datetime
from pathlib import Path

# Configuration
REPO_URL = "https://github.com/BoondockSulfur/InventoryApp.git"
BACKUP_DIR = "backups"
UPDATE_BRANCH = "main"

class UpdateManager:
    def __init__(self):
        self.app_dir = Path(__file__).parent
        self.backup_dir = self.app_dir / BACKUP_DIR
        self.backup_dir.mkdir(exist_ok=True)

    def log(self, message, level="INFO"):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def run_command(self, command, check=True):
        """Execute shell command"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=check,
                capture_output=True,
                text=True
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.CalledProcessError as e:
            return False, e.stdout, e.stderr

    def create_backup(self):
        """Create backup of current installation"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{timestamp}"
        backup_path = self.backup_dir / backup_name

        self.log(f"Creating backup: {backup_name}")

        # Files to backup
        important_files = [
            "app.py",
            "requirements.txt",
            "docker-compose.production.yml",
            "Dockerfile.production",
            ".env",
            "instance",
            "static/uploads"
        ]

        backup_path.mkdir(exist_ok=True)

        for item in important_files:
            src = self.app_dir / item
            if src.exists():
                if src.is_dir():
                    shutil.copytree(src, backup_path / item, dirs_exist_ok=True)
                else:
                    shutil.copy2(src, backup_path / item)

        self.log(f"✅ Backup created: {backup_path}")
        return backup_path

    def check_updates(self):
        """Check if updates are available"""
        self.log("Checking for updates...")

        # Fetch latest changes
        success, stdout, stderr = self.run_command("git fetch origin")
        if not success:
            self.log(f"Failed to fetch updates: {stderr}", "ERROR")
            return False

        # Check if updates available
        success, stdout, stderr = self.run_command(
            f"git rev-list HEAD..origin/{UPDATE_BRANCH} --count"
        )

        if success and stdout.strip() != "0":
            self.log(f"✅ {stdout.strip()} update(s) available")
            return True
        else:
            self.log("✅ System is up to date")
            return False

    def show_changelog(self):
        """Show changes in update"""
        self.log("Changes in this update:")
        success, stdout, stderr = self.run_command(
            f"git log HEAD..origin/{UPDATE_BRANCH} --oneline --decorate"
        )

        if success and stdout:
            print(stdout)
        else:
            self.log("No changelog available", "WARNING")

    def apply_update(self):
        """Apply the update"""
        self.log("Applying update...")

        # Pull latest changes
        success, stdout, stderr = self.run_command(f"git pull origin {UPDATE_BRANCH}")
        if not success:
            self.log(f"Failed to pull updates: {stderr}", "ERROR")
            return False

        self.log("✅ Code updated")

        # Update Python dependencies
        self.log("Updating Python dependencies...")
        success, stdout, stderr = self.run_command(
            "pip install -r requirements.txt --upgrade"
        )

        if not success:
            self.log(f"Warning: Some dependencies failed to update: {stderr}", "WARNING")
        else:
            self.log("✅ Dependencies updated")

        return True

    def run_migrations(self):
        """Run database migrations"""
        self.log("Running database migrations...")

        migrations_dir = self.app_dir / "migrations"
        if not migrations_dir.exists():
            self.log("No migrations directory found", "WARNING")
            return True

        # Get list of migration files
        migration_files = sorted(migrations_dir.glob("*.sql"))

        if not migration_files:
            self.log("No migration files found")
            return True

        # Check if running in Docker
        success, stdout, stderr = self.run_command("docker ps --format '{{.Names}}' | grep inventoryapp_db", check=False)

        if success and "inventoryapp_db" in stdout:
            # Run migrations through Docker
            for migration_file in migration_files:
                self.log(f"Applying migration: {migration_file.name}")
                cmd = f'docker exec -i inventoryapp_db psql -U inventoryapp -d inventoryapp < "{migration_file}"'
                success, stdout, stderr = self.run_command(cmd, check=False)

                if not success and "already exists" not in stderr.lower():
                    self.log(f"Migration warning: {stderr}", "WARNING")
        else:
            self.log("Database migrations must be run manually", "WARNING")
            self.log("Run: psql -U inventoryapp -d inventoryapp < migrations/*.sql")

        self.log("✅ Migrations completed")
        return True

    def restart_services(self):
        """Restart application services"""
        self.log("Restarting services...")

        # Check if Docker Compose is being used
        success, stdout, stderr = self.run_command("docker-compose --version", check=False)

        if success:
            # Restart with Docker Compose
            self.log("Restarting Docker containers...")
            success, stdout, stderr = self.run_command(
                "docker-compose -f docker-compose.production.yml up -d --build"
            )

            if success:
                self.log("✅ Services restarted")
                return True
            else:
                self.log(f"Failed to restart services: {stderr}", "ERROR")
                return False
        else:
            self.log("Docker Compose not found. Please restart services manually.", "WARNING")
            return True

    def rollback(self, backup_path):
        """Rollback to backup"""
        self.log(f"Rolling back to backup: {backup_path}")

        # Restore files from backup
        for item in backup_path.iterdir():
            dest = self.app_dir / item.name
            if item.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)

        self.log("✅ Rollback completed")

    def update(self, auto_restart=True):
        """Main update process"""
        print("=" * 60)
        print("  InventoryApp Update Manager")
        print("=" * 60)
        print()

        # Create backup
        backup_path = self.create_backup()

        try:
            # Check for updates
            if not self.check_updates():
                self.log("No updates available. Exiting.")
                return True

            # Show changelog
            self.show_changelog()

            # Confirm update
            if not auto_restart:
                response = input("\nProceed with update? (yes/no): ")
                if response.lower() not in ['yes', 'y']:
                    self.log("Update cancelled by user")
                    return False

            # Apply update
            if not self.apply_update():
                raise Exception("Failed to apply update")

            # Run migrations
            if not self.run_migrations():
                raise Exception("Failed to run migrations")

            # Restart services
            if auto_restart:
                if not self.restart_services():
                    raise Exception("Failed to restart services")
            else:
                self.log("⚠️  Please restart services manually", "WARNING")

            print()
            print("=" * 60)
            self.log("✅ UPDATE COMPLETED SUCCESSFULLY", "SUCCESS")
            print("=" * 60)

            return True

        except Exception as e:
            self.log(f"Update failed: {e}", "ERROR")
            self.log("Initiating rollback...")
            self.rollback(backup_path)
            return False


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="InventoryApp Update Manager")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only check for updates without applying"
    )
    parser.add_argument(
        "--no-restart",
        action="store_true",
        help="Don't restart services automatically"
    )

    args = parser.parse_args()

    manager = UpdateManager()

    if args.check:
        manager.check_updates()
        manager.show_changelog()
    else:
        success = manager.update(auto_restart=not args.no_restart)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
