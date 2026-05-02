"""
Multi-Tenancy SaaS Module for InventoryApp

Features:
- Tenant isolation (data, users, configurations)
- Tenant provisioning/deprovisioning
- Tenant-specific branding
- Resource quotas and limits
- Billing integration
"""

from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user
from functools import wraps
from datetime import datetime, timedelta
import uuid
import hashlib

db = SQLAlchemy()

# ============================================================================
# Multi-Tenant Models
# ============================================================================

class Tenant(db.Model):
    """
    Tenant/Organization model

    Each tenant has isolated data and configurations
    """
    __tablename__ = 'tenant'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(200), nullable=False, unique=True)
    subdomain = db.Column(db.String(63), nullable=False, unique=True, index=True)

    # Contact info
    company_name = db.Column(db.String(200))
    contact_email = db.Column(db.String(255), nullable=False)
    contact_phone = db.Column(db.String(50))

    # Billing
    plan = db.Column(db.String(50), default='free')  # free, starter, professional, enterprise
    billing_email = db.Column(db.String(255))
    stripe_customer_id = db.Column(db.String(100))
    stripe_subscription_id = db.Column(db.String(100))

    # Quotas
    max_users = db.Column(db.Integer, default=5)
    max_items = db.Column(db.Integer, default=100)
    max_storage_mb = db.Column(db.Integer, default=1024)  # 1GB

    # Features
    features = db.Column(db.JSON, default=lambda: {
        'advanced_analytics': False,
        'api_access': False,
        'custom_branding': False,
        'sso': False,
        'audit_logs': True,
        'blockchain': False,
        'iot_integration': False
    })

    # Branding
    logo_url = db.Column(db.String(500))
    primary_color = db.Column(db.String(7), default='#0d6efd')  # Bootstrap blue
    secondary_color = db.Column(db.String(7), default='#6c757d')  # Bootstrap gray
    custom_domain = db.Column(db.String(255))

    # Status
    status = db.Column(db.String(20), default='active')  # active, suspended, cancelled
    trial_ends_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=14))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Database connection (for isolated database per tenant - enterprise plan)
    database_url = db.Column(db.String(500))  # None = shared database

    # Relationships
    users = db.relationship('User', backref='tenant', lazy='dynamic', foreign_keys='User.tenant_id')

    def __repr__(self):
        return f'<Tenant {self.name}>'

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'subdomain': self.subdomain,
            'company_name': self.company_name,
            'plan': self.plan,
            'status': self.status,
            'features': self.features,
            'branding': {
                'logo_url': self.logo_url,
                'primary_color': self.primary_color,
                'secondary_color': self.secondary_color
            },
            'quotas': {
                'max_users': self.max_users,
                'max_items': self.max_items,
                'max_storage_mb': self.max_storage_mb
            },
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def has_feature(self, feature_name):
        """Check if tenant has access to a feature"""
        return self.features.get(feature_name, False)

    def is_trial_expired(self):
        """Check if trial period has expired"""
        if self.plan != 'free' or not self.trial_ends_at:
            return False
        return datetime.utcnow() > self.trial_ends_at

    def is_quota_exceeded(self, quota_type):
        """Check if tenant has exceeded a quota"""
        if quota_type == 'users':
            return self.users.count() >= self.max_users
        elif quota_type == 'items':
            # This would query the items table filtered by tenant_id
            # For now, placeholder
            return False
        return False

class TenantInvitation(db.Model):
    """
    Invitation for new users to join a tenant
    """
    __tablename__ = 'tenant_invitation'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = db.Column(db.String(36), db.ForeignKey('tenant.id', ondelete='CASCADE'), nullable=False, index=True)
    email = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user')  # admin, verwaltung, user

    # Invitation token
    token = db.Column(db.String(100), unique=True, nullable=False, index=True)

    invited_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=7))
    accepted_at = db.Column(db.DateTime)

    # Relationships
    tenant = db.relationship('Tenant', backref='invitations')
    inviter = db.relationship('User', foreign_keys=[invited_by])

    def generate_token(self):
        """Generate unique invitation token"""
        raw_token = f"{self.tenant_id}:{self.email}:{uuid.uuid4()}"
        self.token = hashlib.sha256(raw_token.encode()).hexdigest()[:32]

    def is_expired(self):
        """Check if invitation has expired"""
        return datetime.utcnow() > self.expires_at

    def accept(self, user):
        """Mark invitation as accepted"""
        self.accepted_at = datetime.utcnow()
        user.tenant_id = self.tenant_id
        user.role = self.role

# ============================================================================
# Middleware & Decorators
# ============================================================================

def get_current_tenant():
    """
    Get current tenant from:
    1. Subdomain (tenant.inventoryapp.com)
    2. Custom domain (example.com)
    3. Header (X-Tenant-ID)
    4. Current user's tenant
    """
    # Try from header (for API requests)
    tenant_id = request.headers.get('X-Tenant-ID')
    if tenant_id:
        return Tenant.query.filter_by(id=tenant_id, status='active').first()

    # Try from subdomain
    host = request.host.split(':')[0]  # Remove port
    if '.' in host:
        subdomain = host.split('.')[0]
        tenant = Tenant.query.filter_by(subdomain=subdomain, status='active').first()
        if tenant:
            return tenant

    # Try from custom domain
    tenant = Tenant.query.filter_by(custom_domain=host, status='active').first()
    if tenant:
        return tenant

    # Try from current user (if authenticated)
    if hasattr(current_user, 'tenant_id') and current_user.tenant_id:
        return Tenant.query.filter_by(id=current_user.tenant_id, status='active').first()

    return None

def tenant_context(f):
    """
    Decorator to ensure tenant context is set
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        g.tenant = get_current_tenant()

        if not g.tenant:
            return jsonify({'error': 'Tenant not found or inactive'}), 403

        # Check if trial expired
        if g.tenant.is_trial_expired():
            return jsonify({
                'error': 'Trial period expired',
                'message': 'Please upgrade your plan to continue using the service'
            }), 402  # Payment Required

        return f(*args, **kwargs)
    return decorated_function

def require_feature(feature_name):
    """
    Decorator to require tenant to have a specific feature
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'tenant') or not g.tenant:
                return jsonify({'error': 'Tenant context required'}), 403

            if not g.tenant.has_feature(feature_name):
                return jsonify({
                    'error': 'Feature not available',
                    'message': f'Your plan does not include {feature_name}. Please upgrade.'
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_quota(quota_type):
    """
    Decorator to check tenant quota before executing
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'tenant') or not g.tenant:
                return jsonify({'error': 'Tenant context required'}), 403

            if g.tenant.is_quota_exceeded(quota_type):
                return jsonify({
                    'error': 'Quota exceeded',
                    'message': f'You have reached the maximum number of {quota_type}. Please upgrade your plan.'
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============================================================================
# SQLAlchemy Query Filtering
# ============================================================================

def filter_by_tenant(query, model):
    """
    Automatically filter query by current tenant

    Usage:
        items = filter_by_tenant(Item.query, Item).all()
    """
    if not hasattr(g, 'tenant') or not g.tenant:
        raise ValueError("No tenant context")

    if hasattr(model, 'tenant_id'):
        return query.filter_by(tenant_id=g.tenant.id)

    return query

# ============================================================================
# Tenant Management API
# ============================================================================

def init_multi_tenant_routes(app):
    """Initialize multi-tenancy routes"""

    @app.route('/api/tenants', methods=['POST'])
    def create_tenant():
        """
        Create a new tenant (sign up for SaaS)

        Required fields:
        - name: Tenant name
        - subdomain: Unique subdomain
        - contact_email: Contact email
        - company_name: Company name (optional)
        """
        data = request.get_json()

        # Validate required fields
        required_fields = ['name', 'subdomain', 'contact_email']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Check if subdomain is already taken
        if Tenant.query.filter_by(subdomain=data['subdomain']).first():
            return jsonify({'error': 'Subdomain already taken'}), 409

        # Check subdomain format (alphanumeric, lowercase, no spaces)
        import re
        if not re.match(r'^[a-z0-9-]+$', data['subdomain']):
            return jsonify({'error': 'Invalid subdomain format. Use lowercase alphanumeric and hyphens only'}), 400

        # Create tenant
        tenant = Tenant(
            name=data['name'],
            subdomain=data['subdomain'],
            contact_email=data['contact_email'],
            company_name=data.get('company_name'),
            contact_phone=data.get('contact_phone'),
            plan='free'  # Start with free trial
        )

        db.session.add(tenant)
        db.session.commit()

        return jsonify({
            'message': 'Tenant created successfully',
            'tenant': tenant.to_dict(),
            'trial_ends_at': tenant.trial_ends_at.isoformat()
        }), 201

    @app.route('/api/tenants/<tenant_id>', methods=['GET'])
    @tenant_context
    def get_tenant(tenant_id):
        """Get tenant details"""
        tenant = Tenant.query.get_or_404(tenant_id)

        # Only allow accessing own tenant or superadmin
        if g.tenant.id != tenant.id and not hasattr(current_user, 'is_superadmin'):
            return jsonify({'error': 'Access denied'}), 403

        return jsonify(tenant.to_dict())

    @app.route('/api/tenants/<tenant_id>', methods=['PUT'])
    @tenant_context
    def update_tenant(tenant_id):
        """Update tenant settings"""
        tenant = Tenant.query.get_or_404(tenant_id)

        # Only allow updating own tenant
        if g.tenant.id != tenant.id:
            return jsonify({'error': 'Access denied'}), 403

        data = request.get_json()

        # Allowed fields to update
        allowed_fields = ['company_name', 'contact_email', 'contact_phone',
                         'logo_url', 'primary_color', 'secondary_color']

        for field in allowed_fields:
            if field in data:
                setattr(tenant, field, data[field])

        db.session.commit()

        return jsonify({
            'message': 'Tenant updated successfully',
            'tenant': tenant.to_dict()
        })

    @app.route('/api/tenants/<tenant_id>/upgrade', methods='POST'])
    @tenant_context
    def upgrade_tenant(tenant_id):
        """Upgrade tenant plan"""
        tenant = Tenant.query.get_or_404(tenant_id)

        if g.tenant.id != tenant.id:
            return jsonify({'error': 'Access denied'}), 403

        data = request.get_json()
        new_plan = data.get('plan')

        # Plan limits
        PLAN_LIMITS = {
            'free': {'max_users': 5, 'max_items': 100, 'max_storage_mb': 1024},
            'starter': {'max_users': 25, 'max_items': 1000, 'max_storage_mb': 10240},
            'professional': {'max_users': 100, 'max_items': 10000, 'max_storage_mb': 102400},
            'enterprise': {'max_users': -1, 'max_items': -1, 'max_storage_mb': -1}  # Unlimited
        }

        # Plan features
        PLAN_FEATURES = {
            'free': {
                'advanced_analytics': False,
                'api_access': False,
                'custom_branding': False,
                'sso': False,
                'audit_logs': True,
                'blockchain': False,
                'iot_integration': False
            },
            'starter': {
                'advanced_analytics': True,
                'api_access': True,
                'custom_branding': False,
                'sso': False,
                'audit_logs': True,
                'blockchain': False,
                'iot_integration': False
            },
            'professional': {
                'advanced_analytics': True,
                'api_access': True,
                'custom_branding': True,
                'sso': True,
                'audit_logs': True,
                'blockchain': True,
                'iot_integration': True
            },
            'enterprise': {
                'advanced_analytics': True,
                'api_access': True,
                'custom_branding': True,
                'sso': True,
                'audit_logs': True,
                'blockchain': True,
                'iot_integration': True
            }
        }

        if new_plan not in PLAN_LIMITS:
            return jsonify({'error': 'Invalid plan'}), 400

        # Update plan, quotas, and features
        tenant.plan = new_plan
        tenant.max_users = PLAN_LIMITS[new_plan]['max_users']
        tenant.max_items = PLAN_LIMITS[new_plan]['max_items']
        tenant.max_storage_mb = PLAN_LIMITS[new_plan]['max_storage_mb']
        tenant.features = PLAN_FEATURES[new_plan]

        db.session.commit()

        return jsonify({
            'message': f'Tenant upgraded to {new_plan} plan',
            'tenant': tenant.to_dict()
        })

    @app.route('/api/tenants/<tenant_id>/invitations', methods=['POST'])
    @tenant_context
    @check_quota('users')
    def invite_user(tenant_id):
        """Invite a user to the tenant"""
        tenant = Tenant.query.get_or_404(tenant_id)

        if g.tenant.id != tenant.id:
            return jsonify({'error': 'Access denied'}), 403

        data = request.get_json()
        email = data.get('email')
        role = data.get('role', 'user')

        if not email:
            return jsonify({'error': 'Email required'}), 400

        # Check if user already exists
        from app import User  # Import User model
        existing_user = User.query.filter_by(email=email, tenant_id=tenant.id).first()
        if existing_user:
            return jsonify({'error': 'User already exists in this tenant'}), 409

        # Create invitation
        invitation = TenantInvitation(
            tenant_id=tenant.id,
            email=email,
            role=role,
            invited_by=current_user.id if hasattr(current_user, 'id') else None
        )
        invitation.generate_token()

        db.session.add(invitation)
        db.session.commit()

        # TODO: Send invitation email

        return jsonify({
            'message': 'Invitation sent',
            'invitation': {
                'id': invitation.id,
                'email': invitation.email,
                'token': invitation.token,
                'expires_at': invitation.expires_at.isoformat()
            }
        }), 201

# ============================================================================
# Tenant Migration Helpers
# ============================================================================

def add_tenant_column_to_models():
    """
    Migration helper to add tenant_id to existing models

    Run this after adding Tenant model
    """
    from flask_migrate import Migrate

    # Models that need tenant_id
    MODELS_TO_MIGRATE = [
        'item', 'category', 'location', 'loan', 'maintenance',
        'budget_entry', 'budget_transaction', 'repair_log',
        'notification', 'saved_filter', 'team'
    ]

    migration_sql = []
    for table in MODELS_TO_MIGRATE:
        migration_sql.append(f"""
        ALTER TABLE {table}
        ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);

        ALTER TABLE {table}
        ADD CONSTRAINT fk_{table}_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE;

        CREATE INDEX IF NOT EXISTS idx_{table}_tenant_id ON {table}(tenant_id);
        """)

    return '\n'.join(migration_sql)

if __name__ == '__main__':
    print("Multi-Tenant Module for InventoryApp")
    print("=" * 50)
    print("\nRun add_tenant_column_to_models() to get migration SQL")
