"""
Mobile API Routes
REST API endpoints optimized for mobile apps
- Authentication with JWT
- Barcode scanning support
- Offline sync capabilities
- Push notification registration
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import jwt
import os

mobile_api = Blueprint('mobile_api', __name__, url_prefix='/api/v1/mobile')


# ============================================================================
# Helper Functions
# ============================================================================

def generate_jwt_token(user_id):
    """Generate a JWT token for a user"""
    secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=1),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, secret_key, algorithm='HS256')


def verify_jwt_token(token):
    """Verify and decode a JWT token"""
    try:
        secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def jwt_required(f):
    """Decorator to require JWT authentication"""
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        if not token:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401

        payload = verify_jwt_token(token)
        if not payload:
            return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401

        # Pass user_id to the route function
        return f(payload['user_id'], *args, **kwargs)

    return decorated_function


# ============================================================================
# Authentication Endpoints
# ============================================================================

@mobile_api.route('/auth/login', methods=['POST'])
def mobile_login():
    """
    Mobile login endpoint - returns JWT token

    Request:
        {
            "username": "user@example.com",
            "password": "password123"
        }

    Response:
        {
            "success": true,
            "token": "jwt_token_here",
            "user": {
                "id": 1,
                "username": "user",
                "email": "user@example.com",
                "role": "user"
            },
            "expires_in": 86400
        }
    """
    try:
        from app import User, db

        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        # Generate JWT token
        token = generate_jwt_token(user.id)

        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role if hasattr(user, 'role') else 'user'
            },
            'expires_in': 86400  # 24 hours
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@mobile_api.route('/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh an existing JWT token"""
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        if not token:
            return jsonify({'success': False, 'error': 'Token required'}), 401

        # Verify and decode token
        payload = verify_jwt_token(token)
        if not payload:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401

        # Generate new token
        new_token = generate_jwt_token(payload['user_id'])

        return jsonify({
            'success': True,
            'token': new_token,
            'expires_in': 86400
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# Items Endpoints
# ============================================================================

@mobile_api.route('/items', methods=['GET'])
@jwt_required
def get_items_mobile():
    """
    Get items with pagination and filtering

    Query params:
        - page: Page number (default: 1)
        - per_page: Items per page (default: 20)
        - category: Filter by category
        - status: Filter by status
        - search: Search query
        - updated_since: ISO timestamp for sync (optional)

    Response:
        {
            "success": true,
            "items": [...],
            "pagination": {
                "page": 1,
                "per_page": 20,
                "total": 100,
                "pages": 5
            },
            "server_time": "2025-01-15T10:30:00Z"
        }
    """
    try:
        from app import Item, db

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        category = request.args.get('category')
        status = request.args.get('status')
        search = request.args.get('search')
        updated_since = request.args.get('updated_since')

        # Build query
        query = Item.query

        if category:
            query = query.filter_by(category=category)

        if status:
            query = query.filter_by(status=status)

        if search:
            search_term = f"%{search}%"
            query = query.filter(
                db.or_(
                    Item.name.ilike(search_term),
                    Item.description.ilike(search_term),
                    Item.serial_number.ilike(search_term)
                )
            )

        if updated_since:
            try:
                sync_time = datetime.fromisoformat(updated_since.replace('Z', '+00:00'))
                query = query.filter(Item.updated_at > sync_time)
            except ValueError:
                pass

        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        items = [{
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'category': item.category if hasattr(item, 'category') else None,
            'serial_number': item.serial_number,
            'asset_tag': item.asset_tag,
            'location': item.location,
            'status': item.status if hasattr(item, 'status') else 'available',
            'image_url': item.image_url if hasattr(item, 'image_url') else None,
            'qr_code': item.qr_code if hasattr(item, 'qr_code') else None,
            'created_at': item.created_at.isoformat() if hasattr(item, 'created_at') else None,
            'updated_at': item.updated_at.isoformat() if hasattr(item, 'updated_at') else None,
        } for item in pagination.items]

        return jsonify({
            'success': True,
            'items': items,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages
            },
            'server_time': datetime.utcnow().isoformat() + 'Z'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@mobile_api.route('/items/<int:item_id>', methods=['GET'])
@jwt_required
def get_item_detail_mobile(item_id):
    """Get detailed information about a specific item"""
    try:
        from app import Item

        item = Item.query.get_or_404(item_id)

        return jsonify({
            'success': True,
            'item': {
                'id': item.id,
                'name': item.name,
                'description': item.description,
                'category': item.category if hasattr(item, 'category') else None,
                'serial_number': item.serial_number,
                'asset_tag': item.asset_tag,
                'location': item.location,
                'status': item.status if hasattr(item, 'status') else 'available',
                'image_url': item.image_url if hasattr(item, 'image_url') else None,
                'qr_code': item.qr_code if hasattr(item, 'qr_code') else None,
                'purchase_date': item.purchase_date.isoformat() if hasattr(item, 'purchase_date') and item.purchase_date else None,
                'warranty_end': item.warranty_end.isoformat() if hasattr(item, 'warranty_end') and item.warranty_end else None,
                'value': float(item.value) if hasattr(item, 'value') and item.value else None,
                'created_at': item.created_at.isoformat() if hasattr(item, 'created_at') else None,
                'updated_at': item.updated_at.isoformat() if hasattr(item, 'updated_at') else None,
            }
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@mobile_api.route('/items/scan', methods=['POST'])
@jwt_required
def scan_item_mobile():
    """
    Scan a barcode/QR code to find an item

    Request:
        {
            "code": "barcode_or_qr_value",
            "code_type": "qr|barcode|serial"
        }

    Response:
        {
            "success": true,
            "item": {...}
        }
    """
    try:
        from app import Item

        data = request.get_json()
        code = data.get('code')
        code_type = data.get('code_type', 'qr')

        if not code:
            return jsonify({'success': False, 'error': 'Code required'}), 400

        # Search for item based on code type
        if code_type == 'qr':
            item = Item.query.filter_by(qr_code=code).first()
        elif code_type == 'serial':
            item = Item.query.filter_by(serial_number=code).first()
        else:
            item = Item.query.filter_by(asset_tag=code).first()

        if not item:
            return jsonify({'success': False, 'error': 'Item not found'}), 404

        return jsonify({
            'success': True,
            'item': {
                'id': item.id,
                'name': item.name,
                'description': item.description,
                'category': item.category if hasattr(item, 'category') else None,
                'serial_number': item.serial_number,
                'asset_tag': item.asset_tag,
                'location': item.location,
                'status': item.status if hasattr(item, 'status') else 'available',
                'image_url': item.image_url if hasattr(item, 'image_url') else None,
            }
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# Loans Endpoints
# ============================================================================

@mobile_api.route('/loans', methods=['GET'])
@jwt_required
def get_loans_mobile(user_id):
    """Get user's loans"""
    try:
        from app import Loan

        loans = Loan.query.filter_by(user_id=user_id).order_by(Loan.loan_date.desc()).all()

        return jsonify({
            'success': True,
            'loans': [{
                'id': loan.id,
                'item_id': loan.item_id,
                'item_name': loan.item.name if loan.item else None,
                'loan_date': loan.loan_date.isoformat() if loan.loan_date else None,
                'due_date': loan.due_date.isoformat() if loan.due_date else None,
                'return_date': loan.return_date.isoformat() if loan.return_date else None,
                'status': loan.status if hasattr(loan, 'status') else 'active',
            } for loan in loans]
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@mobile_api.route('/loans', methods=['POST'])
@jwt_required
def create_loan_mobile(user_id):
    """
    Create a new loan request

    Request:
        {
            "item_id": 123,
            "due_date": "2025-02-01T00:00:00Z",
            "notes": "Optional notes"
        }
    """
    try:
        from app import Loan, Item, db

        data = request.get_json()
        item_id = data.get('item_id')
        due_date_str = data.get('due_date')
        notes = data.get('notes', '')

        if not item_id:
            return jsonify({'success': False, 'error': 'Item ID required'}), 400

        item = Item.query.get_or_404(item_id)

        # Check if item is available
        if hasattr(item, 'status') and item.status != 'available':
            return jsonify({'success': False, 'error': 'Item not available'}), 400

        # Parse due date
        due_date = None
        if due_date_str:
            try:
                due_date = datetime.fromisoformat(due_date_str.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid due date format'}), 400

        # Create loan
        loan = Loan(
            user_id=user_id,
            item_id=item_id,
            loan_date=datetime.utcnow(),
            due_date=due_date,
            notes=notes
        )

        db.session.add(loan)
        db.session.commit()

        return jsonify({
            'success': True,
            'loan': {
                'id': loan.id,
                'item_id': loan.item_id,
                'loan_date': loan.loan_date.isoformat(),
                'due_date': loan.due_date.isoformat() if loan.due_date else None,
                'status': 'pending'
            }
        }), 201

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# Notifications Endpoints
# ============================================================================

@mobile_api.route('/notifications/register', methods=['POST'])
@jwt_required
def register_push_token(user_id):
    """
    Register device for push notifications

    Request:
        {
            "device_token": "fcm_or_apns_token",
            "platform": "ios|android"
        }
    """
    try:
        from app import db

        data = request.get_json()
        device_token = data.get('device_token')
        platform = data.get('platform')

        if not device_token or not platform:
            return jsonify({'success': False, 'error': 'Device token and platform required'}), 400

        # In a real implementation, save this to a DeviceToken model
        # For now, just acknowledge
        return jsonify({
            'success': True,
            'message': 'Push notification token registered'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# Sync Endpoints for Offline Support
# ============================================================================

@mobile_api.route('/sync/changes', methods=['POST'])
@jwt_required
def sync_changes(user_id):
    """
    Sync offline changes made by the mobile app

    Request:
        {
            "changes": [
                {
                    "entity_type": "loan",
                    "action": "create|update|delete",
                    "data": {...},
                    "client_timestamp": "2025-01-15T10:30:00Z"
                }
            ],
            "last_sync": "2025-01-15T09:00:00Z"
        }

    Response:
        {
            "success": true,
            "conflicts": [],
            "server_changes": [...],
            "server_time": "2025-01-15T10:35:00Z"
        }
    """
    try:
        data = request.get_json()
        changes = data.get('changes', [])
        last_sync = data.get('last_sync')

        conflicts = []
        applied_changes = []

        # Process each change
        for change in changes:
            entity_type = change.get('entity_type')
            action = change.get('action')
            change_data = change.get('data')

            # Apply change (with conflict detection)
            # In a real implementation, you'd handle conflicts more sophisticated
            applied_changes.append(change)

        # Get server changes since last sync
        server_changes = []
        if last_sync:
            try:
                sync_time = datetime.fromisoformat(last_sync.replace('Z', '+00:00'))
                # Query for changes since sync_time
                # server_changes = get_changes_since(sync_time)
            except ValueError:
                pass

        return jsonify({
            'success': True,
            'conflicts': conflicts,
            'applied_changes': len(applied_changes),
            'server_changes': server_changes,
            'server_time': datetime.utcnow().isoformat() + 'Z'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
