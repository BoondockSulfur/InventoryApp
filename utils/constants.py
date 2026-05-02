# -*- coding: utf-8 -*-
"""
Constants Module for InventoryApp
Centralizes magic strings and numbers used throughout the application
"""

# ============================================================================
# User Roles
# ============================================================================

class UserRole:
    """User role constants"""
    ADMIN = 'admin'
    VERWALTUNG = 'verwaltung'
    MITARBEITER = 'mitarbeiter'
    KUNDE = 'kunde'

    @classmethod
    def all_roles(cls):
        """Return list of all valid roles"""
        return [cls.ADMIN, cls.VERWALTUNG, cls.MITARBEITER, cls.KUNDE]

    @classmethod
    def is_valid(cls, role):
        """Check if role is valid"""
        return role in cls.all_roles()


# ============================================================================
# Item Status
# ============================================================================

class ItemStatus:
    """Item status constants"""
    AVAILABLE = 'available'
    BORROWED = 'borrowed'
    DEFECTIVE = 'defective'
    MAINTENANCE = 'maintenance'
    RESERVED = 'reserved'

    @classmethod
    def all_statuses(cls):
        """Return list of all valid statuses"""
        return [cls.AVAILABLE, cls.BORROWED, cls.DEFECTIVE, cls.MAINTENANCE, cls.RESERVED]


# ============================================================================
# Ticket Status
# ============================================================================

class TicketStatus:
    """Ticket status constants"""
    OPEN = 'open'
    IN_PROGRESS = 'in_progress'
    WAITING = 'waiting'
    RESOLVED = 'resolved'
    CLOSED = 'closed'

    @classmethod
    def all_statuses(cls):
        """Return list of all valid statuses"""
        return [cls.OPEN, cls.IN_PROGRESS, cls.WAITING, cls.RESOLVED, cls.CLOSED]


class TicketPriorityLevel:
    """Ticket priority constants"""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    URGENT = 'urgent'

    @classmethod
    def all_priorities(cls):
        """Return list of all valid priorities"""
        return [cls.LOW, cls.MEDIUM, cls.HIGH, cls.URGENT]


class TicketCategory:
    """Ticket category constants"""
    HARDWARE = 'hardware'
    SOFTWARE = 'software'
    ACCESS = 'access'
    OTHER = 'other'

    @classmethod
    def all_categories(cls):
        """Return list of all valid categories"""
        return [cls.HARDWARE, cls.SOFTWARE, cls.ACCESS, cls.OTHER]


# ============================================================================
# Maintenance Status
# ============================================================================

class MaintenanceStatus:
    """Maintenance status constants"""
    SCHEDULED = 'scheduled'
    IN_PROGRESS = 'in_progress'
    COMPLETED = 'completed'
    OVERDUE = 'overdue'
    CANCELLED = 'cancelled'

    @classmethod
    def all_statuses(cls):
        """Return list of all valid statuses"""
        return [cls.SCHEDULED, cls.IN_PROGRESS, cls.COMPLETED, cls.OVERDUE, cls.CANCELLED]


# ============================================================================
# Notification Types
# ============================================================================

class NotificationType:
    """Notification type constants"""
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'
    SUCCESS = 'success'
    LOAN_DUE = 'loan_due'
    LOAN_OVERDUE = 'loan_overdue'
    MAINTENANCE_DUE = 'maintenance_due'
    MAINTENANCE_OVERDUE = 'maintenance_overdue'
    TICKET_ASSIGNED = 'ticket_assigned'
    TICKET_RESPONSE = 'ticket_response'
    APPROVAL_REQUEST = 'approval_request'

    @classmethod
    def all_types(cls):
        """Return list of all valid notification types"""
        return [
            cls.INFO, cls.WARNING, cls.ERROR, cls.SUCCESS,
            cls.LOAN_DUE, cls.LOAN_OVERDUE,
            cls.MAINTENANCE_DUE, cls.MAINTENANCE_OVERDUE,
            cls.TICKET_ASSIGNED, cls.TICKET_RESPONSE,
            cls.APPROVAL_REQUEST
        ]


# ============================================================================
# Permissions
# ============================================================================

class Permission:
    """Permission action constants"""
    VIEW = 'view'
    CREATE = 'create'
    UPDATE = 'update'
    DELETE = 'delete'
    MANAGE = 'manage'
    APPROVE = 'approve'

    # Resource types
    RESOURCE_ITEM = 'item'
    RESOURCE_LOAN = 'loan'
    RESOURCE_TICKET = 'ticket'
    RESOURCE_USER = 'user'
    RESOURCE_CATEGORY = 'category'
    RESOURCE_LOCATION = 'location'
    RESOURCE_MAINTENANCE = 'maintenance'

    @classmethod
    def all_actions(cls):
        """Return list of all valid actions"""
        return [cls.VIEW, cls.CREATE, cls.UPDATE, cls.DELETE, cls.MANAGE, cls.APPROVE]


# ============================================================================
# Application Settings
# ============================================================================

class AppSettings:
    """Application-wide settings and limits"""

    # Pagination
    DEFAULT_PAGE_SIZE = 50
    MAX_PAGE_SIZE = 100

    # File uploads
    MAX_FILE_SIZE_MB = 16
    MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
    ALLOWED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
    ALLOWED_DOCUMENT_EXTENSIONS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt'}

    # Session
    SESSION_LIFETIME_SECONDS = 3600  # 1 hour

    # Logging
    LOG_FILE_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
    LOG_BACKUP_COUNT = 3

    # Rate limiting
    DEFAULT_RATE_LIMIT = "100/hour"
    API_RATE_LIMIT = "1000/hour"
    LOGIN_RATE_LIMIT = "5/minute"

    # Security
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = False

    # QR Code
    QR_CODE_VERSION = 1
    QR_CODE_BOX_SIZE = 10
    QR_CODE_BORDER = 4

    # Dell API
    DELL_API_TIMEOUT_SECONDS = 30
    DELL_WARRANTY_CACHE_HOURS = 24

    # Email
    EMAIL_RETRY_ATTEMPTS = 3
    EMAIL_RETRY_DELAY_SECONDS = 5


# ============================================================================
# HTTP Status Codes
# ============================================================================

class HTTPStatus:
    """Common HTTP status codes"""
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204

    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    TOO_MANY_REQUESTS = 429

    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    SERVICE_UNAVAILABLE = 503


# ============================================================================
# Audit Actions
# ============================================================================

class AuditAction:
    """Audit log action types"""
    CREATE = 'create'
    UPDATE = 'update'
    DELETE = 'delete'
    VIEW = 'view'
    LOGIN = 'login'
    LOGOUT = 'logout'
    LOGIN_FAILED = 'login_failed'
    LOAN = 'loan'
    RETURN = 'return'
    QR_SCAN = 'qr_scan'
    RFID_SCAN = 'rfid_scan'
    BARCODE_SCAN = 'barcode_scan'
    EXPORT = 'export'
    IMPORT = 'import'
    PRINT = 'print'
    EMAIL_SENT = 'email_sent'
    API_CALL = 'api_call'


# ============================================================================
# Depreciation Rates
# ============================================================================

class DepreciationRate:
    """Standard depreciation rates by category"""
    COMPUTER = 0.33  # 3 years
    LAPTOP = 0.33    # 3 years
    MONITOR = 0.20   # 5 years
    FURNITURE = 0.10 # 10 years
    TOOL = 0.20      # 5 years
    VEHICLE = 0.25   # 4 years
    DEFAULT = 0.20   # 5 years

    @classmethod
    def get_rate(cls, category_name):
        """Get depreciation rate for category"""
        category_mapping = {
            'computer': cls.COMPUTER,
            'laptop': cls.LAPTOP,
            'monitor': cls.MONITOR,
            'furniture': cls.FURNITURE,
            'tool': cls.TOOL,
            'vehicle': cls.VEHICLE,
        }
        return category_mapping.get(category_name.lower(), cls.DEFAULT)


# ============================================================================
# Date Formats
# ============================================================================

class DateFormat:
    """Standard date/time formats"""
    DATE_DISPLAY = '%d.%m.%Y'  # 23.12.2025
    DATE_ISO = '%Y-%m-%d'       # 2025-12-23
    DATETIME_DISPLAY = '%d.%m.%Y %H:%M'  # 23.12.2025 14:30
    DATETIME_ISO = '%Y-%m-%dT%H:%M:%S'   # 2025-12-23T14:30:00
    TIME_DISPLAY = '%H:%M'      # 14:30
    FILENAME_TIMESTAMP = '%Y%m%d_%H%M%S'  # 20251223_143000


# ============================================================================
# Webhook Colors
# ============================================================================

class WebhookColor:
    """Webhook notification colors (for Slack, Discord, etc.)"""
    INFO = '#17a2b8'     # Blue
    SUCCESS = '#28a745'  # Green
    WARNING = '#ffc107'  # Yellow
    DANGER = '#dc3545'   # Red
    PRIMARY = '#007bff'  # Blue
    SECONDARY = '#6c757d'  # Gray


# ============================================================================
# Flash Message Categories
# ============================================================================

class FlashCategory:
    """Flash message categories for Bootstrap alerts"""
    SUCCESS = 'success'      # Green alert - successful operations
    DANGER = 'danger'        # Red alert - errors and failures
    WARNING = 'warning'      # Yellow alert - warnings
    INFO = 'info'            # Blue alert - informational messages
    PRIMARY = 'primary'      # Blue alert - primary information
    SECONDARY = 'secondary'  # Gray alert - secondary information
    LIGHT = 'light'          # Light gray alert
    DARK = 'dark'            # Dark alert

    @classmethod
    def all_categories(cls):
        """Return list of all valid categories"""
        return [cls.SUCCESS, cls.DANGER, cls.WARNING, cls.INFO,
                cls.PRIMARY, cls.SECONDARY, cls.LIGHT, cls.DARK]


# ============================================================================
# Export Constants
# ============================================================================

# Make commonly used constants available at module level for convenience
ALL_USER_ROLES = UserRole.all_roles()
ALL_ITEM_STATUSES = ItemStatus.all_statuses()
ALL_TICKET_STATUSES = TicketStatus.all_statuses()
ALL_TICKET_PRIORITIES = TicketPriorityLevel.all_priorities()
ALL_MAINTENANCE_STATUSES = MaintenanceStatus.all_statuses()
