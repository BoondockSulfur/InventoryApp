# -*- coding: utf-8 -*-
"""
Custom Exception Classes for InventoryApp
Provides a hierarchy of exceptions for better error handling and reporting
"""

from typing import Optional, Dict, Any


# ============================================================================
# Base Exception
# ============================================================================

class InventoryAppException(Exception):
    """
    Base exception for all InventoryApp-specific exceptions.

    Attributes:
        message: Human-readable error message
        status_code: HTTP status code for API responses
        payload: Additional error context data
    """

    def __init__(self, message: str, status_code: int = 500, payload: Optional[Dict[str, Any]] = None):
        """
        Initialize the exception.

        Args:
            message: Error message
            status_code: HTTP status code (default: 500)
            payload: Additional error context
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.payload = payload or {}

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for JSON responses.

        Returns:
            Dictionary with error information
        """
        error_dict = {
            'error': {
                'type': self.__class__.__name__,
                'message': self.message,
                'status_code': self.status_code
            }
        }
        if self.payload:
            error_dict['error']['details'] = self.payload
        return error_dict


# ============================================================================
# Resource Not Found Exceptions
# ============================================================================

class ResourceNotFoundException(InventoryAppException):
    """Base exception for resource not found errors"""

    def __init__(self, resource_type: str, resource_id: Any):
        message = f"{resource_type} with ID '{resource_id}' not found"
        super().__init__(message, status_code=404, payload={
            'resource_type': resource_type,
            'resource_id': str(resource_id)
        })


class ItemNotFoundException(ResourceNotFoundException):
    """Item not found exception"""

    def __init__(self, item_id: int):
        super().__init__('Item', item_id)


class UserNotFoundException(ResourceNotFoundException):
    """User not found exception"""

    def __init__(self, user_id: int):
        super().__init__('User', user_id)


class LoanNotFoundException(ResourceNotFoundException):
    """Loan not found exception"""

    def __init__(self, loan_id: int):
        super().__init__('Loan', loan_id)


class TicketNotFoundException(ResourceNotFoundException):
    """Ticket not found exception"""

    def __init__(self, ticket_id: int):
        super().__init__('Ticket', ticket_id)


class CategoryNotFoundException(ResourceNotFoundException):
    """Category not found exception"""

    def __init__(self, category_id: int):
        super().__init__('Category', category_id)


class LocationNotFoundException(ResourceNotFoundException):
    """Location not found exception"""

    def __init__(self, location_id: int):
        super().__init__('Location', location_id)


# ============================================================================
# Permission and Authorization Exceptions
# ============================================================================

class PermissionDeniedException(InventoryAppException):
    """Permission denied exception"""

    def __init__(self, action: str, resource_type: str, user_id: Optional[int] = None):
        message = f"Permission denied for action '{action}' on resource '{resource_type}'"
        super().__init__(message, status_code=403, payload={
            'action': action,
            'resource_type': resource_type,
            'user_id': user_id
        })


class AuthenticationRequiredException(InventoryAppException):
    """Authentication required exception"""

    def __init__(self):
        super().__init__(
            "Authentication required to access this resource",
            status_code=401
        )


class InvalidCredentialsException(InventoryAppException):
    """Invalid credentials exception"""

    def __init__(self):
        super().__init__(
            "Invalid username or password",
            status_code=401
        )


class AccountDisabledException(InventoryAppException):
    """Account disabled exception"""

    def __init__(self, username: str):
        super().__init__(
            f"Account '{username}' is disabled",
            status_code=403,
            payload={'username': username}
        )


# ============================================================================
# Validation Exceptions
# ============================================================================

class ValidationException(InventoryAppException):
    """Base validation exception"""

    def __init__(self, message: str, field: Optional[str] = None, value: Any = None):
        payload = {}
        if field:
            payload['field'] = field
        if value is not None:
            payload['value'] = str(value)

        super().__init__(message, status_code=400, payload=payload)


class InvalidInputException(ValidationException):
    """Invalid input exception"""

    def __init__(self, field: str, message: str, value: Any = None):
        super().__init__(
            f"Invalid value for field '{field}': {message}",
            field=field,
            value=value
        )


class MissingRequiredFieldException(ValidationException):
    """Missing required field exception"""

    def __init__(self, field: str):
        super().__init__(
            f"Required field '{field}' is missing",
            field=field
        )


class DuplicateResourceException(InventoryAppException):
    """Duplicate resource exception"""

    def __init__(self, resource_type: str, field: str, value: str):
        message = f"{resource_type} with {field} '{value}' already exists"
        super().__init__(message, status_code=409, payload={
            'resource_type': resource_type,
            'field': field,
            'value': value
        })


# ============================================================================
# Business Logic Exceptions
# ============================================================================

class ItemNotAvailableException(InventoryAppException):
    """Item not available for loan exception"""

    def __init__(self, item_id: int, reason: str):
        super().__init__(
            f"Item {item_id} is not available: {reason}",
            status_code=409,
            payload={'item_id': item_id, 'reason': reason}
        )


class LoanAlreadyReturnedException(InventoryAppException):
    """Loan already returned exception"""

    def __init__(self, loan_id: int):
        super().__init__(
            f"Loan {loan_id} has already been returned",
            status_code=400,
            payload={'loan_id': loan_id}
        )


class ReservationConflictException(InventoryAppException):
    """Reservation conflict exception"""

    def __init__(self, item_id: int, start_date: str, end_date: str):
        super().__init__(
            f"Item {item_id} is already reserved for the period {start_date} to {end_date}",
            status_code=409,
            payload={
                'item_id': item_id,
                'start_date': start_date,
                'end_date': end_date
            }
        )


class MaintenanceInProgressException(InventoryAppException):
    """Maintenance in progress exception"""

    def __init__(self, item_id: int):
        super().__init__(
            f"Item {item_id} is currently under maintenance",
            status_code=409,
            payload={'item_id': item_id}
        )


# ============================================================================
# External Service Exceptions
# ============================================================================

class ExternalServiceException(InventoryAppException):
    """Base exception for external service errors"""

    def __init__(self, service_name: str, message: str, original_error: Optional[Exception] = None):
        full_message = f"External service '{service_name}' error: {message}"
        payload = {'service_name': service_name}
        if original_error:
            payload['original_error'] = str(original_error)

        super().__init__(full_message, status_code=503, payload=payload)


class DellAPIException(ExternalServiceException):
    """Dell API exception"""

    def __init__(self, message: str, original_error: Optional[Exception] = None):
        super().__init__('Dell Warranty API', message, original_error)


class EmailServiceException(ExternalServiceException):
    """Email service exception"""

    def __init__(self, message: str, original_error: Optional[Exception] = None):
        super().__init__('Email Service', message, original_error)


class PrinterServiceException(ExternalServiceException):
    """Printer service exception"""

    def __init__(self, message: str, original_error: Optional[Exception] = None):
        super().__init__('Printer Service', message, original_error)


class ElasticsearchException(ExternalServiceException):
    """Elasticsearch exception"""

    def __init__(self, message: str, original_error: Optional[Exception] = None):
        super().__init__('Elasticsearch', message, original_error)


# ============================================================================
# File Operation Exceptions
# ============================================================================

class FileOperationException(InventoryAppException):
    """Base file operation exception"""

    def __init__(self, operation: str, filename: str, message: str):
        super().__init__(
            f"File {operation} failed for '{filename}': {message}",
            status_code=500,
            payload={'operation': operation, 'filename': filename}
        )


class InvalidFileTypeException(InventoryAppException):
    """Invalid file type exception"""

    def __init__(self, filename: str, allowed_types: list):
        super().__init__(
            f"Invalid file type for '{filename}'. Allowed types: {', '.join(allowed_types)}",
            status_code=400,
            payload={'filename': filename, 'allowed_types': allowed_types}
        )


class FileTooLargeException(InventoryAppException):
    """File too large exception"""

    def __init__(self, filename: str, size_mb: float, max_size_mb: int):
        super().__init__(
            f"File '{filename}' ({size_mb:.1f} MB) exceeds maximum size of {max_size_mb} MB",
            status_code=413,
            payload={
                'filename': filename,
                'size_mb': size_mb,
                'max_size_mb': max_size_mb
            }
        )


# ============================================================================
# Database Exceptions
# ============================================================================

class DatabaseException(InventoryAppException):
    """Base database exception"""

    def __init__(self, message: str, original_error: Optional[Exception] = None):
        payload = {}
        if original_error:
            payload['original_error'] = str(original_error)

        super().__init__(
            f"Database error: {message}",
            status_code=500,
            payload=payload
        )


class DatabaseConstraintViolation(DatabaseException):
    """Database constraint violation exception"""

    def __init__(self, constraint: str, message: str):
        super().__init__(f"Constraint violation '{constraint}': {message}")


# ============================================================================
# Rate Limiting Exceptions
# ============================================================================

class RateLimitExceededException(InventoryAppException):
    """Rate limit exceeded exception"""

    def __init__(self, limit: str, retry_after: Optional[int] = None):
        message = f"Rate limit exceeded: {limit}"
        payload = {'limit': limit}
        if retry_after:
            message += f". Retry after {retry_after} seconds"
            payload['retry_after'] = retry_after

        super().__init__(message, status_code=429, payload=payload)


# ============================================================================
# Configuration Exceptions
# ============================================================================

class ConfigurationException(InventoryAppException):
    """Configuration exception"""

    def __init__(self, setting: str, message: str):
        super().__init__(
            f"Configuration error for '{setting}': {message}",
            status_code=500,
            payload={'setting': setting}
        )


class MissingConfigurationException(ConfigurationException):
    """Missing configuration exception"""

    def __init__(self, setting: str):
        super().__init__(setting, f"Required setting '{setting}' is not configured")


# ============================================================================
# Import/Export Exceptions
# ============================================================================

class ImportException(InventoryAppException):
    """Import operation exception"""

    def __init__(self, message: str, row: Optional[int] = None, column: Optional[str] = None):
        payload = {}
        if row is not None:
            payload['row'] = row
        if column:
            payload['column'] = column

        super().__init__(
            f"Import error: {message}",
            status_code=400,
            payload=payload
        )


class ExportException(InventoryAppException):
    """Export operation exception"""

    def __init__(self, format_type: str, message: str):
        super().__init__(
            f"Export to {format_type} failed: {message}",
            status_code=500,
            payload={'format': format_type}
        )


# ============================================================================
# Workflow Exceptions
# ============================================================================

class WorkflowException(InventoryAppException):
    """Workflow engine exception"""

    def __init__(self, workflow_name: str, message: str):
        super().__init__(
            f"Workflow '{workflow_name}' error: {message}",
            status_code=500,
            payload={'workflow': workflow_name}
        )


class InvalidWorkflowStateException(WorkflowException):
    """Invalid workflow state exception"""

    def __init__(self, workflow_name: str, current_state: str, attempted_transition: str):
        super().__init__(
            workflow_name,
            f"Cannot transition from '{current_state}' via '{attempted_transition}'"
        )
        self.payload.update({
            'current_state': current_state,
            'attempted_transition': attempted_transition
        })
