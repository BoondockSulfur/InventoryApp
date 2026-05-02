# -*- coding: utf-8 -*-
"""
Input Validation Utilities for InventoryApp
============================================
Provides validation functions for user input, file uploads, and data formats.
"""

import re
import os
from urllib.parse import urlparse
from typing import Optional, Tuple


# ============================================================================
# Email Validation
# ============================================================================

def validate_email(email: str) -> bool:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        bool: True if email format is valid, False otherwise

    Examples:
        >>> validate_email('user@example.com')
        True
        >>> validate_email('invalid-email')
        False
    """
    if not email or not isinstance(email, str):
        return False

    # RFC 5322 simplified email regex
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email.strip()))


# ============================================================================
# Serial Number Validation
# ============================================================================

def validate_serial_number(serial: str, min_length: int = 4, max_length: int = 50) -> Tuple[bool, Optional[str]]:
    """
    Validate serial number format.

    Serial numbers must be alphanumeric and within specified length range.

    Args:
        serial: Serial number to validate
        min_length: Minimum allowed length (default: 4)
        max_length: Maximum allowed length (default: 50)

    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)

    Examples:
        >>> validate_serial_number('ABC123')
        (True, None)
        >>> validate_serial_number('AB')
        (False, 'Serial number must be between 4 and 50 characters')
    """
    if not serial or not isinstance(serial, str):
        return False, "Serial number is required"

    serial = serial.strip()

    if len(serial) < min_length or len(serial) > max_length:
        return False, f"Serial number must be between {min_length} and {max_length} characters"

    if not serial.replace('-', '').replace('_', '').isalnum():
        return False, "Serial number must be alphanumeric (hyphens and underscores allowed)"

    return True, None


# ============================================================================
# Filename Sanitization
# ============================================================================

def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize uploaded filenames to prevent directory traversal and other attacks.

    Args:
        filename: Original filename
        max_length: Maximum allowed filename length (default: 255)

    Returns:
        str: Sanitized filename safe for filesystem storage

    Examples:
        >>> sanitize_filename('../../etc/passwd')
        'etc_passwd'
        >>> sanitize_filename('document (1).pdf')
        'document_1.pdf'
    """
    if not filename:
        return 'unnamed_file'

    # Remove path components (directory traversal protection)
    filename = filename.split('/')[-1].split('\\')[-1]

    # Replace spaces with underscores
    filename = filename.replace(' ', '_')

    # Remove non-alphanumeric characters except dots, hyphens, underscores
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)

    # Remove leading dots (hidden files)
    filename = filename.lstrip('.')

    # Collapse multiple underscores
    filename = re.sub(r'_{2,}', '_', filename)

    # Limit length (preserve extension if possible)
    if len(filename) > max_length:
        name_parts = filename.rsplit('.', 1)
        if len(name_parts) == 2:
            name, ext = name_parts
            # Keep extension, truncate name
            max_name_length = max_length - len(ext) - 1
            filename = f"{name[:max_name_length]}.{ext}"
        else:
            filename = filename[:max_length]

    return filename or 'unnamed_file'


# ============================================================================
# URL Validation
# ============================================================================

def validate_url(url: str, require_https: bool = False) -> bool:
    """
    Validate URL format.

    Args:
        url: URL to validate
        require_https: If True, only accept HTTPS URLs (default: False)

    Returns:
        bool: True if URL format is valid, False otherwise

    Examples:
        >>> validate_url('https://example.com')
        True
        >>> validate_url('ftp://files.example.com')
        True
        >>> validate_url('invalid-url')
        False
    """
    if not url or not isinstance(url, str):
        return False

    try:
        result = urlparse(url.strip())

        # Check scheme and netloc are present
        if not all([result.scheme, result.netloc]):
            return False

        # Optionally require HTTPS
        if require_https and result.scheme != 'https':
            return False

        # Check for valid scheme
        if result.scheme not in ['http', 'https', 'ftp', 'ftps']:
            return False

        return True
    except Exception:
        return False


# ============================================================================
# File Extension Validation
# ============================================================================

def validate_file_extension(filename: str, allowed_extensions: set) -> Tuple[bool, Optional[str]]:
    """
    Validate file extension against allowed list.

    Args:
        filename: Filename to validate
        allowed_extensions: Set of allowed extensions (with dots, e.g., {'.jpg', '.png'})

    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)

    Examples:
        >>> validate_file_extension('image.jpg', {'.jpg', '.png'})
        (True, None)
        >>> validate_file_extension('malware.exe', {'.jpg', '.png'})
        (False, 'File type not allowed. Allowed types: .jpg, .png')
    """
    if not filename:
        return False, "Filename is required"

    # Get file extension
    _, ext = os.path.splitext(filename.lower())

    if not ext:
        return False, "File must have an extension"

    if ext not in allowed_extensions:
        allowed = ', '.join(sorted(allowed_extensions))
        return False, f"File type not allowed. Allowed types: {allowed}"

    return True, None


# ============================================================================
# Barcode Validation
# ============================================================================

def validate_barcode(barcode: str, barcode_type: str = 'any') -> Tuple[bool, Optional[str]]:
    """
    Validate barcode format.

    Args:
        barcode: Barcode string to validate
        barcode_type: Type of barcode ('ean13', 'upc', 'code128', 'any')

    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)

    Examples:
        >>> validate_barcode('1234567890123', 'ean13')
        (True, None)
        >>> validate_barcode('ABC-123', 'code128')
        (True, None)
    """
    if not barcode or not isinstance(barcode, str):
        return False, "Barcode is required"

    barcode = barcode.strip()

    if barcode_type == 'ean13':
        if not barcode.isdigit() or len(barcode) != 13:
            return False, "EAN-13 barcode must be exactly 13 digits"

    elif barcode_type == 'upc':
        if not barcode.isdigit() or len(barcode) != 12:
            return False, "UPC barcode must be exactly 12 digits"

    elif barcode_type == 'code128':
        # Code128 supports alphanumeric and some special characters
        if not re.match(r'^[A-Za-z0-9\-_. ]+$', barcode):
            return False, "Code128 barcode contains invalid characters"

    elif barcode_type == 'any':
        # Generic validation - alphanumeric plus common separators
        if not re.match(r'^[A-Za-z0-9\-_. ]+$', barcode):
            return False, "Barcode contains invalid characters"

        if len(barcode) < 3 or len(barcode) > 128:
            return False, "Barcode must be between 3 and 128 characters"

    else:
        return False, f"Unknown barcode type: {barcode_type}"

    return True, None


# ============================================================================
# RFID Tag Validation
# ============================================================================

def validate_rfid_tag(rfid_tag: str) -> Tuple[bool, Optional[str]]:
    """
    Validate RFID tag format.

    RFID tags are typically hexadecimal strings of varying length.

    Args:
        rfid_tag: RFID tag string to validate

    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)

    Examples:
        >>> validate_rfid_tag('E2801195')
        (True, None)
        >>> validate_rfid_tag('ZZZZ')
        (False, 'RFID tag must be a valid hexadecimal string')
    """
    if not rfid_tag or not isinstance(rfid_tag, str):
        return False, "RFID tag is required"

    rfid_tag = rfid_tag.strip().upper()

    # Remove common separators
    rfid_tag_clean = rfid_tag.replace(':', '').replace('-', '').replace(' ', '')

    # Validate hexadecimal
    if not re.match(r'^[0-9A-F]+$', rfid_tag_clean):
        return False, "RFID tag must be a valid hexadecimal string"

    # Typical RFID tags are 8-32 hex characters
    if len(rfid_tag_clean) < 4 or len(rfid_tag_clean) > 64:
        return False, "RFID tag length out of valid range (4-64 hex characters)"

    return True, None


# ============================================================================
# Password Strength Validation
# ============================================================================

def validate_password_strength(password: str, min_length: int = 8,
                               require_uppercase: bool = True,
                               require_lowercase: bool = True,
                               require_digit: bool = True,
                               require_special: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validate password strength based on complexity requirements.

    Args:
        password: Password to validate
        min_length: Minimum password length (default: 8)
        require_uppercase: Require at least one uppercase letter (default: True)
        require_lowercase: Require at least one lowercase letter (default: True)
        require_digit: Require at least one digit (default: True)
        require_special: Require at least one special character (default: False)

    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)

    Examples:
        >>> validate_password_strength('Password123')
        (True, None)
        >>> validate_password_strength('weak')
        (False, 'Password must be at least 8 characters')
    """
    if not password:
        return False, "Password is required"

    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters"

    if require_uppercase and not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    if require_lowercase and not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    if require_digit and not re.search(r'\d', password):
        return False, "Password must contain at least one digit"

    if require_special and not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        return False, "Password must contain at least one special character"

    return True, None


# ============================================================================
# Integer Range Validation
# ============================================================================

def validate_integer_range(value: any, min_val: int = None, max_val: int = None,
                          field_name: str = "Value") -> Tuple[bool, Optional[str]]:
    """
    Validate that a value is an integer within specified range.

    Args:
        value: Value to validate
        min_val: Minimum allowed value (inclusive, optional)
        max_val: Maximum allowed value (inclusive, optional)
        field_name: Name of field for error messages (default: "Value")

    Returns:
        Tuple[bool, Optional[str]]: (is_valid, error_message)

    Examples:
        >>> validate_integer_range(5, 1, 10)
        (True, None)
        >>> validate_integer_range(15, 1, 10)
        (False, 'Value must be between 1 and 10')
    """
    try:
        int_value = int(value)
    except (TypeError, ValueError):
        return False, f"{field_name} must be a valid integer"

    if min_val is not None and int_value < min_val:
        if max_val is not None:
            return False, f"{field_name} must be between {min_val} and {max_val}"
        return False, f"{field_name} must be at least {min_val}"

    if max_val is not None and int_value > max_val:
        if min_val is not None:
            return False, f"{field_name} must be between {min_val} and {max_val}"
        return False, f"{field_name} must be at most {max_val}"

    return True, None
