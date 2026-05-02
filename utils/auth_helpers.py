# -*- coding: utf-8 -*-
"""
Authentication and Authorization Helper Functions
==================================================
Provides reusable helpers for permission checking, flash messages, and database operations.
"""

from flask import flash, current_app
from utils.constants import UserRole, FlashCategory


# ============================================================================
# Permission Checking
# ============================================================================

def check_user_permission(user, permission_name: str) -> bool:
    """
    Centralized permission check with logging.

    Admin users bypass all permission checks.
    Other users are checked against their specific permissions.

    Args:
        user: User object to check permissions for
        permission_name: Name of the permission to check

    Returns:
        bool: True if user has permission, False otherwise

    Examples:
        >>> check_user_permission(admin_user, 'delete_item')
        True
        >>> check_user_permission(regular_user, 'delete_item')
        False
    """
    if not user:
        return False

    # Admin users have all permissions
    if user.role == UserRole.ADMIN:
        return True

    # Check specific permission
    try:
        has_permission = user.has_permission(permission_name)

        if not has_permission:
            current_app.logger.warning(
                f"Permission denied: User {user.id} ({user.role}) attempted '{permission_name}'"
            )

        return has_permission

    except AttributeError:
        # User model doesn't have has_permission method
        current_app.logger.error(
            f"User model missing has_permission method for user {user.id}"
        )
        return False

    except Exception as e:
        current_app.logger.error(
            f"Permission check failed for user {user.id}: {e}"
        )
        return False


def check_role_permission(user, allowed_roles: list) -> bool:
    """
    Check if user's role is in the list of allowed roles.

    Args:
        user: User object to check
        allowed_roles: List of allowed role strings

    Returns:
        bool: True if user's role is in allowed_roles, False otherwise

    Examples:
        >>> check_role_permission(user, [UserRole.ADMIN, UserRole.VERWALTUNG])
        True
    """
    if not user or not allowed_roles:
        return False

    return user.role in allowed_roles


# ============================================================================
# Flash Message Helpers
# ============================================================================

def flash_success(message: str):
    """
    Flash a success message (green alert).

    Args:
        message: Success message to display

    Examples:
        >>> flash_success("Item created successfully!")
    """
    flash(message, FlashCategory.SUCCESS)


def flash_error(message: str, log_error: str = None):
    """
    Flash an error message (red alert) with optional logging.

    Args:
        message: Error message to display to user
        log_error: Optional detailed error for logging (not shown to user)

    Examples:
        >>> flash_error("Failed to save item", "Database constraint violation: unique_serial")
    """
    if log_error:
        current_app.logger.error(log_error)

    flash(message, FlashCategory.DANGER)


def flash_warning(message: str):
    """
    Flash a warning message (yellow alert).

    Args:
        message: Warning message to display

    Examples:
        >>> flash_warning("Item warranty expires soon!")
    """
    flash(message, FlashCategory.WARNING)


def flash_info(message: str):
    """
    Flash an informational message (blue alert).

    Args:
        message: Info message to display

    Examples:
        >>> flash_info("System maintenance scheduled for tonight")
    """
    flash(message, FlashCategory.INFO)


# ============================================================================
# Database Operation Helpers
# ============================================================================

def safe_commit(db, success_message: str = None, error_message: str = "Operation failed") -> bool:
    """
    Safely commit database transaction with automatic rollback on error.

    Args:
        db: SQLAlchemy database instance
        success_message: Message to flash on successful commit (optional)
        error_message: Message to flash on commit failure (default: "Operation failed")

    Returns:
        bool: True if commit succeeded, False if it failed

    Examples:
        >>> if safe_commit(db, "Item saved successfully!"):
        ...     return redirect(url_for('items'))
    """
    try:
        db.session.commit()

        if success_message:
            flash_success(success_message)

        return True

    except Exception as e:
        db.session.rollback()
        flash_error(error_message, f"Database commit failed: {e}")
        return False


def safe_delete(db, obj, success_message: str = None, error_message: str = "Delete operation failed") -> bool:
    """
    Safely delete database object with automatic rollback on error.

    Args:
        db: SQLAlchemy database instance
        obj: Database object to delete
        success_message: Message to flash on successful delete (optional)
        error_message: Message to flash on delete failure

    Returns:
        bool: True if delete succeeded, False if it failed

    Examples:
        >>> if safe_delete(db, item, "Item deleted successfully!"):
        ...     return redirect(url_for('items'))
    """
    try:
        db.session.delete(obj)
        db.session.commit()

        if success_message:
            flash_success(success_message)

        return True

    except Exception as e:
        db.session.rollback()
        flash_error(error_message, f"Database delete failed: {e}")
        return False


def safe_add(db, obj, success_message: str = None, error_message: str = "Add operation failed") -> bool:
    """
    Safely add database object with automatic rollback on error.

    Args:
        db: SQLAlchemy database instance
        obj: Database object to add
        success_message: Message to flash on successful add (optional)
        error_message: Message to flash on add failure

    Returns:
        bool: True if add succeeded, False if it failed

    Examples:
        >>> new_item = Item(name="Laptop", serial="ABC123")
        >>> if safe_add(db, new_item, "Item created successfully!"):
        ...     return redirect(url_for('items'))
    """
    try:
        db.session.add(obj)
        db.session.commit()

        if success_message:
            flash_success(success_message)

        return True

    except Exception as e:
        db.session.rollback()
        flash_error(error_message, f"Database add failed: {e}")
        return False


# ============================================================================
# Logging Helpers
# ============================================================================

def log_user_action(user, action: str, details: str = None):
    """
    Log user action for audit trail.

    Args:
        user: User who performed the action
        action: Action performed (e.g., 'create_item', 'delete_user')
        details: Optional additional details about the action

    Examples:
        >>> log_user_action(current_user, 'create_item', f'Created item: {item.name}')
    """
    user_id = user.id if user else 'anonymous'
    user_role = user.role if user else 'unknown'

    log_message = f"User {user_id} ({user_role}) performed action: {action}"

    if details:
        log_message += f" - {details}"

    current_app.logger.info(log_message)


def log_security_event(event_type: str, user=None, details: str = None, level: str = 'warning'):
    """
    Log security-related events.

    Args:
        event_type: Type of security event (e.g., 'failed_login', 'permission_denied')
        user: User involved in the event (optional)
        details: Additional details about the event
        level: Log level ('info', 'warning', 'error', 'critical')

    Examples:
        >>> log_security_event('failed_login', user=None, details='IP: 192.168.1.100')
    """
    user_info = f"User {user.id}" if user else "Anonymous"

    log_message = f"[SECURITY] {event_type} - {user_info}"

    if details:
        log_message += f" - {details}"

    log_func = getattr(current_app.logger, level, current_app.logger.warning)
    log_func(log_message)


# ============================================================================
# Response Helpers
# ============================================================================

def json_success(data=None, message: str = "Success", status_code: int = 200):
    """
    Create standardized JSON success response.

    Args:
        data: Response data (optional)
        message: Success message
        status_code: HTTP status code (default: 200)

    Returns:
        tuple: (json_dict, status_code)

    Examples:
        >>> return json_success({'item_id': 123}, "Item created")
    """
    response = {
        'success': True,
        'message': message
    }

    if data is not None:
        response['data'] = data

    return response, status_code


def json_error(message: str = "An error occurred", errors=None, status_code: int = 400):
    """
    Create standardized JSON error response.

    Args:
        message: Error message
        errors: Optional detailed error information
        status_code: HTTP status code (default: 400)

    Returns:
        tuple: (json_dict, status_code)

    Examples:
        >>> return json_error("Item not found", status_code=404)
    """
    response = {
        'success': False,
        'message': message
    }

    if errors is not None:
        response['errors'] = errors

    return response, status_code
