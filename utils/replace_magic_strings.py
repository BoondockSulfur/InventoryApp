#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Magic String Replacement Script
================================
Replaces hardcoded magic strings in app.py with constants.

This script performs systematic replacements of:
- Flash message categories ('success', 'danger', etc.) -> FlashCategory constants
- User roles ('admin', 'verwaltung', etc.) -> UserRole constants
- HTTP status codes (200, 404, etc.) -> HTTPStatus constants
- Ticket status values -> TicketStatus constants

Run with: python utils/replace_magic_strings.py
"""

import re
import sys
from pathlib import Path

# Path to app.py
APP_PY_PATH = Path(__file__).parent.parent / 'app.py'


def read_file(path):
    """Read file content."""
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def write_file(path, content):
    """Write content to file."""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


def replace_flash_categories(content):
    """Replace flash message categories with FlashCategory constants."""
    replacements = [
        (r"flash\(([^,]+),\s*['\"]success['\"]\)", r"flash(\1, FlashCategory.SUCCESS)"),
        (r"flash\(([^,]+),\s*['\"]danger['\"]\)", r"flash(\1, FlashCategory.DANGER)"),
        (r"flash\(([^,]+),\s*['\"]warning['\"]\)", r"flash(\1, FlashCategory.WARNING)"),
        (r"flash\(([^,]+),\s*['\"]info['\"]\)", r"flash(\1, FlashCategory.INFO)"),
        (r"flash\(([^,]+),\s*['\"]primary['\"]\)", r"flash(\1, FlashCategory.PRIMARY)"),
    ]

    count = 0
    for pattern, replacement in replacements:
        new_content, n = re.subn(pattern, replacement, content)
        count += n
        content = new_content

    return content, count


def replace_user_roles(content):
    """Replace user role strings with UserRole constants."""
    replacements = [
        (r"\.role\s*==\s*['\"]admin['\"]", ".role == UserRole.ADMIN"),
        (r"\.role\s*==\s*['\"]verwaltung['\"]", ".role == UserRole.VERWALTUNG"),
        (r"\.role\s*==\s*['\"]mitarbeiter['\"]", ".role == UserRole.MITARBEITER"),
        (r"\.role\s*==\s*['\"]kunde['\"]", ".role == UserRole.KUNDE"),
        (r"role\s*=\s*['\"]admin['\"]", "role = UserRole.ADMIN"),
        (r"role\s*=\s*['\"]verwaltung['\"]", "role = UserRole.VERWALTUNG"),
        (r"role\s*=\s*['\"]mitarbeiter['\"]", "role = UserRole.MITARBEITER"),
        (r"role\s*=\s*['\"]kunde['\"]", "role = UserRole.KUNDE"),
    ]

    count = 0
    for pattern, replacement in replacements:
        new_content, n = re.subn(pattern, replacement, content)
        count += n
        content = new_content

    return content, count


def replace_http_status_codes(content):
    """Replace numeric HTTP status codes with HTTPStatus constants."""
    # Only replace status codes that are clearly HTTP status codes
    # (used with abort(), jsonify return values, etc.)
    replacements = [
        (r"\babort\(200\)", "abort(HTTPStatus.OK)"),
        (r"\babort\(201\)", "abort(HTTPStatus.CREATED)"),
        (r"\babort\(400\)", "abort(HTTPStatus.BAD_REQUEST)"),
        (r"\babort\(401\)", "abort(HTTPStatus.UNAUTHORIZED)"),
        (r"\babort\(403\)", "abort(HTTPStatus.FORBIDDEN)"),
        (r"\babort\(404\)", "abort(HTTPStatus.NOT_FOUND)"),
        (r"\babort\(405\)", "abort(HTTPStatus.METHOD_NOT_ALLOWED)"),
        (r"\babort\(500\)", "abort(HTTPStatus.INTERNAL_SERVER_ERROR)"),

        # In jsonify returns: , 200) or , 404) etc.
        (r",\s*200\)", ", HTTPStatus.OK)"),
        (r",\s*201\)", ", HTTPStatus.CREATED)"),
        (r",\s*400\)", ", HTTPStatus.BAD_REQUEST)"),
        (r",\s*401\)", ", HTTPStatus.UNAUTHORIZED)"),
        (r",\s*403\)", ", HTTPStatus.FORBIDDEN)"),
        (r",\s*404\)", ", HTTPStatus.NOT_FOUND)"),
        (r",\s*500\)", ", HTTPStatus.INTERNAL_SERVER_ERROR)"),
    ]

    count = 0
    for pattern, replacement in replacements:
        new_content, n = re.subn(pattern, replacement, content)
        count += n
        content = new_content

    return content, count


def replace_ticket_status(content):
    """Replace ticket status strings with TicketStatus constants."""
    replacements = [
        (r"status\s*==\s*['\"]open['\"]", "status == TicketStatus.OPEN"),
        (r"status\s*==\s*['\"]in_progress['\"]", "status == TicketStatus.IN_PROGRESS"),
        (r"status\s*==\s*['\"]waiting['\"]", "status == TicketStatus.WAITING"),
        (r"status\s*==\s*['\"]resolved['\"]", "status == TicketStatus.RESOLVED"),
        (r"status\s*==\s*['\"]closed['\"]", "status == TicketStatus.CLOSED"),
        (r"status\s*=\s*['\"]open['\"]", "status = TicketStatus.OPEN"),
        (r"status\s*=\s*['\"]in_progress['\"]", "status = TicketStatus.IN_PROGRESS"),
        (r"status\s*=\s*['\"]waiting['\"]", "status = TicketStatus.WAITING"),
        (r"status\s*=\s*['\"]resolved['\"]", "status = TicketStatus.RESOLVED"),
        (r"status\s*=\s*['\"]closed['\"]", "status = TicketStatus.CLOSED"),
    ]

    count = 0
    for pattern, replacement in replacements:
        new_content, n = re.subn(pattern, replacement, content)
        count += n
        content = new_content

    return content, count


def main():
    """Main function."""
    print("\n" + "="*70)
    print("MAGIC STRING REPLACEMENT SCRIPT")
    print("="*70 + "\n")

    if not APP_PY_PATH.exists():
        print(f"ERROR: app.py not found at {APP_PY_PATH}")
        return 1

    print(f"Reading {APP_PY_PATH}...")
    content = read_file(APP_PY_PATH)
    original_content = content

    total_replacements = 0

    # Flash categories
    print("\n>>> Replacing Flash Message Categories")
    print("-" * 70)
    content, count = replace_flash_categories(content)
    print(f"  Replaced {count} flash message categories")
    total_replacements += count

    # User roles
    print("\n>>> Replacing User Roles")
    print("-" * 70)
    content, count = replace_user_roles(content)
    print(f"  Replaced {count} user role strings")
    total_replacements += count

    # HTTP status codes
    print("\n>>> Replacing HTTP Status Codes")
    print("-" * 70)
    content, count = replace_http_status_codes(content)
    print(f"  Replaced {count} HTTP status codes")
    total_replacements += count

    # Ticket status
    print("\n>>> Replacing Ticket Status Values")
    print("-" * 70)
    content, count = replace_ticket_status(content)
    print(f"  Replaced {count} ticket status values")
    total_replacements += count

    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"  Total replacements: {total_replacements}")

    if total_replacements > 0:
        # Create backup
        backup_path = APP_PY_PATH.with_suffix('.py.backup_constants')
        print(f"\n  Creating backup: {backup_path}")
        write_file(backup_path, original_content)

        # Write updated content
        print(f"  Writing updated app.py...")
        write_file(APP_PY_PATH, content)

        print("\n  SUCCESS! Magic strings replaced with constants.")
        print(f"  Backup saved as: {backup_path}")
    else:
        print("\n  No replacements needed - all magic strings already use constants!")

    return 0


if __name__ == '__main__':
    sys.exit(main())
