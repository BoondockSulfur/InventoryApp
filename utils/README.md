# Utils Module - Quick Reference Guide

This directory contains utility modules that provide reusable functions, constants, and helpers for the InventoryApp.

## Module Overview

| Module | Lines | Purpose | Key Features |
|--------|-------|---------|--------------|
| `constants.py` | 354 | Application-wide constants | User roles, status codes, HTTP codes, flash categories |
| `validators.py` | 399 | Input validation | Email, URL, serial numbers, barcodes, RFID tags |
| `auth_helpers.py` | 352 | Authentication & helpers | Permission checking, flash messages, DB operations |
| `exceptions.py` | 471 | Custom exceptions | Application-specific error types |
| `__init__.py` | 100 | Package initialization | Exports commonly used items |

**Total: 1,880 lines of reusable utility code**

---

## Quick Reference

### Constants (constants.py)

#### User Roles
```python
from utils.constants import UserRole

if user.role == UserRole.ADMIN:
    # Admin user
    pass

# Available roles:
# UserRole.ADMIN
# UserRole.VERWALTUNG
# UserRole.MITARBEITER
# UserRole.KUNDE
```

#### Flash Message Categories
```python
from utils.constants import FlashCategory

flash('Success!', FlashCategory.SUCCESS)    # Green
flash('Error!', FlashCategory.DANGER)       # Red
flash('Warning!', FlashCategory.WARNING)    # Yellow
flash('Info', FlashCategory.INFO)           # Blue
```

#### HTTP Status Codes
```python
from utils.constants import HTTPStatus

abort(HTTPStatus.FORBIDDEN)                 # 403
abort(HTTPStatus.NOT_FOUND)                 # 404
return jsonify({'msg': 'OK'}), HTTPStatus.OK  # 200
```

#### Ticket Status
```python
from utils.constants import TicketStatus

ticket.status = TicketStatus.OPEN           # 'open'
ticket.status = TicketStatus.IN_PROGRESS    # 'in_progress'
ticket.status = TicketStatus.RESOLVED       # 'resolved'
```

#### Item Status
```python
from utils.constants import ItemStatus

item.status = ItemStatus.AVAILABLE          # 'available'
item.status = ItemStatus.BORROWED           # 'borrowed'
item.status = ItemStatus.MAINTENANCE        # 'maintenance'
```

---

### Validators (validators.py)

#### Email Validation
```python
from utils.validators import validate_email

if validate_email('user@example.com'):
    # Valid email
    pass
```

#### Serial Number Validation
```python
from utils.validators import validate_serial_number

is_valid, error_msg = validate_serial_number('ABC123')
if is_valid:
    # Valid serial number
    pass
else:
    flash(error_msg, FlashCategory.DANGER)
```

#### Filename Sanitization
```python
from utils.validators import sanitize_filename

# Prevents directory traversal attacks
safe_filename = sanitize_filename('../../etc/passwd')
# Returns: 'etc_passwd'

safe_filename = sanitize_filename('my document (1).pdf')
# Returns: 'my_document_1.pdf'
```

#### URL Validation
```python
from utils.validators import validate_url

if validate_url('https://example.com'):
    # Valid URL
    pass

# Require HTTPS only
if validate_url('https://example.com', require_https=True):
    # Valid HTTPS URL
    pass
```

#### Barcode Validation
```python
from utils.validators import validate_barcode

is_valid, error = validate_barcode('1234567890123', 'ean13')
is_valid, error = validate_barcode('ABC-123', 'code128')
is_valid, error = validate_barcode('ANY123', 'any')  # Generic
```

#### RFID Tag Validation
```python
from utils.validators import validate_rfid_tag

is_valid, error = validate_rfid_tag('E2801195')
if is_valid:
    # Valid RFID tag (hexadecimal)
    pass
```

#### Password Strength
```python
from utils.validators import validate_password_strength

is_valid, error = validate_password_strength(
    'MyPassword123',
    min_length=8,
    require_uppercase=True,
    require_lowercase=True,
    require_digit=True,
    require_special=False
)
```

#### File Extension Validation
```python
from utils.validators import validate_file_extension
from utils.constants import AppSettings

allowed = AppSettings.ALLOWED_IMAGE_EXTENSIONS
is_valid, error = validate_file_extension('photo.jpg', allowed)
```

---

### Auth Helpers (auth_helpers.py)

#### Flash Message Helpers
```python
from utils.auth_helpers import (
    flash_success, flash_error, flash_warning, flash_info
)

flash_success("Item created successfully!")
flash_error("Failed to save", "Database error: constraint violation")
flash_warning("Item warranty expires soon")
flash_info("Maintenance scheduled for tonight")
```

#### Permission Checking
```python
from utils.auth_helpers import check_user_permission

if check_user_permission(current_user, 'delete_item'):
    # User has permission
    db.session.delete(item)
else:
    # Permission denied (automatically logged)
    abort(HTTPStatus.FORBIDDEN)
```

#### Role-Based Access
```python
from utils.auth_helpers import check_role_permission
from utils.constants import UserRole

allowed_roles = [UserRole.ADMIN, UserRole.VERWALTUNG]
if check_role_permission(current_user, allowed_roles):
    # User has required role
    pass
```

#### Safe Database Operations
```python
from utils.auth_helpers import safe_commit, safe_add, safe_delete

# Safe commit with automatic rollback on error
if safe_commit(db, "Item saved successfully!"):
    return redirect(url_for('items'))
else:
    # Error already flashed and logged
    return render_template('error.html')

# Safe add
new_item = Item(name="Laptop", serial="ABC123")
if safe_add(db, new_item, "Item created!"):
    return redirect(url_for('items'))

# Safe delete
if safe_delete(db, item, "Item deleted!"):
    return redirect(url_for('items'))
```

#### Logging Helpers
```python
from utils.auth_helpers import log_user_action, log_security_event

# Audit trail logging
log_user_action(current_user, 'create_item', f'Created item: {item.name}')

# Security event logging
log_security_event('failed_login', user=None, details='IP: 192.168.1.100')
log_security_event('permission_denied', user=current_user, details='delete_user')
```

#### JSON Response Helpers
```python
from utils.auth_helpers import json_success, json_error
from utils.constants import HTTPStatus

# Success response
return json_success({'item_id': 123}, "Item created")
# Returns: ({'success': True, 'message': '...', 'data': {...}}, 200)

# Error response
return json_error("Item not found", status_code=HTTPStatus.NOT_FOUND)
# Returns: ({'success': False, 'message': '...'}, 404)
```

---

## Common Patterns

### Creating a New Item (with validation & error handling)
```python
from utils.validators import validate_serial_number, sanitize_filename
from utils.auth_helpers import safe_add, flash_error
from utils.constants import FlashCategory

# Validate input
is_valid, error = validate_serial_number(serial)
if not is_valid:
    flash_error(error)
    return redirect(url_for('items_new'))

# Sanitize filename
if image_file:
    filename = sanitize_filename(image_file.filename)
    image_file.save(os.path.join(upload_folder, filename))

# Create item
new_item = Item(
    name=name,
    serial=serial,
    image_path=filename
)

# Safe database add with automatic error handling
if safe_add(db, new_item, "Item created successfully!"):
    log_user_action(current_user, 'create_item', f'Created: {name}')
    return redirect(url_for('items'))
else:
    # Error already flashed and logged
    return redirect(url_for('items_new'))
```

### Checking Permissions
```python
from utils.auth_helpers import check_user_permission
from utils.constants import HTTPStatus

@app.route('/admin/users')
@login_required
def admin_users():
    if not check_user_permission(current_user, 'manage_users'):
        abort(HTTPStatus.FORBIDDEN)

    # User has permission - proceed
    users = User.query.all()
    return render_template('admin/users.html', users=users)
```

### Validating Form Input
```python
from utils.validators import validate_email, validate_url
from utils.auth_helpers import flash_error

# Email validation
if not validate_email(form.email.data):
    flash_error("Invalid email address")
    return redirect(url_for('profile'))

# URL validation (optional field)
if form.website.data and not validate_url(form.website.data):
    flash_error("Invalid website URL")
    return redirect(url_for('profile'))
```

---

## Benefits

### Code Quality
- ✅ **DRY Principle** - No code duplication for common operations
- ✅ **Consistency** - Same patterns throughout the application
- ✅ **Type Safety** - Constants prevent typos and invalid values
- ✅ **Self-Documenting** - Clear, descriptive function names

### Security
- ✅ **Input Validation** - Prevent injection attacks
- ✅ **Filename Sanitization** - Prevent directory traversal
- ✅ **Password Strength** - Enforce security policies
- ✅ **Audit Logging** - Track security events

### Maintainability
- ✅ **Centralized Logic** - Change once, updates everywhere
- ✅ **Easy Refactoring** - Update constants to change behavior
- ✅ **Better Testing** - Test validators independently
- ✅ **IDE Support** - Autocomplete for constants and functions

### Developer Experience
- ✅ **Less Boilerplate** - Common patterns simplified
- ✅ **Clear Errors** - Validation functions return descriptive errors
- ✅ **Automatic Logging** - Security events logged automatically
- ✅ **Standardized APIs** - Consistent function signatures

---

## Migration Guide

### Old Pattern → New Pattern

#### Flash Messages
```python
# OLD:
flash('Success', 'success')
flash('Error', 'danger')

# NEW:
from utils.auth_helpers import flash_success, flash_error
flash_success('Success')
flash_error('Error')
```

#### Database Operations
```python
# OLD:
try:
    db.session.add(item)
    db.session.commit()
    flash('Item created', 'success')
except Exception as e:
    db.session.rollback()
    flash('Failed to create item', 'danger')
    app.logger.error(f'Error: {e}')

# NEW:
from utils.auth_helpers import safe_add
safe_add(db, item, "Item created successfully!")
```

#### Permission Checking
```python
# OLD:
if current_user.role != 'admin':
    abort(403)

# NEW:
from utils.auth_helpers import check_role_permission
from utils.constants import UserRole, HTTPStatus

if not check_role_permission(current_user, [UserRole.ADMIN]):
    abort(HTTPStatus.FORBIDDEN)
```

---

## Testing

### Example Test Cases

```python
import unittest
from utils.validators import validate_email, validate_serial_number

class TestValidators(unittest.TestCase):
    def test_email_validation(self):
        self.assertTrue(validate_email('user@example.com'))
        self.assertFalse(validate_email('invalid-email'))

    def test_serial_validation(self):
        is_valid, _ = validate_serial_number('ABC123')
        self.assertTrue(is_valid)

        is_valid, error = validate_serial_number('AB')
        self.assertFalse(is_valid)
        self.assertIn('between 4 and 50', error)
```

---

## Performance Notes

- All validators are **stateless** - safe for concurrent use
- Regex patterns are **compiled once** at module import
- Database helpers use **single transactions** for better performance
- Constants are **immutable** - no overhead at runtime

---

## Contributing

When adding new utility functions:

1. **Add to appropriate module** (validators, auth_helpers, constants)
2. **Include docstring** with examples
3. **Add type hints** for parameters and return values
4. **Return consistent types** (bool for simple checks, tuple for detailed validation)
5. **Add to this README** under appropriate section

---

## Support

For questions or issues with utility modules:
- Check this README for usage examples
- Review function docstrings for detailed documentation
- See `PHASE_2_COMPLETION_REPORT.md` for implementation details

---

*Last updated: 2025-12-23*
