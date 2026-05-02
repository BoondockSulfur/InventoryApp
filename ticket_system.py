# -*- coding: utf-8 -*-
"""
Enhanced Ticket System for InventoryApp
Provides flexible ticket management with custom fields, workflows, and SLA rules
"""

from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
import json

# Create blueprint
ticket_bp = Blueprint('tickets', __name__, url_prefix='/tickets')

# ═══════════════════════════════════════════════════════════════════════════
# ─── NOTE: Enhanced ticket models are defined in app.py ───────────────────
# ─── TicketCategory, TicketPriority, TicketStatus, TicketCustomField, etc.
# ═══════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════
# ─── TICKET SETTINGS & CONFIGURATION ───────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

def init_ticket_routes(app, db, require_permission):
    """Initialize ticket management routes"""
    from functools import wraps

    # Create a wrapper that uses login_required if require_permission is None
    def auth_required(permission=None):
        def decorator(f):
            @wraps(f)
            @login_required
            def decorated_function(*args, **kwargs):
                return f(*args, **kwargs)

            # If require_permission is available, also check permission
            if require_permission is not None and permission is not None:
                decorated_function = require_permission(permission)(decorated_function)

            return decorated_function
        return decorator

    @ticket_bp.route('/settings')
    @auth_required('manage_settings')
    def settings():
        """Ticket system settings page"""
        return render_template('tickets/settings.html')

    @ticket_bp.route('/documentation')
    @login_required
    def documentation():
        """Ticket system documentation page"""
        return render_template('tickets/documentation.html')

    @ticket_bp.route('/settings/categories')
    @auth_required('manage_settings')
    def manage_categories():
        """Manage ticket categories"""
        from app import TicketCategory
        categories = TicketCategory.query.all()
        return render_template('tickets/manage_categories.html', categories=categories)

    @ticket_bp.route('/settings/priorities')
    @auth_required('manage_settings')
    def manage_priorities():
        """Manage ticket priorities"""
        from app import TicketPriority
        priorities = TicketPriority.query.order_by(TicketPriority.level.desc()).all()
        return render_template('tickets/manage_priorities.html', priorities=priorities)

    @ticket_bp.route('/settings/statuses')
    @auth_required('manage_settings')
    def manage_statuses():
        """Manage ticket statuses and workflows"""
        from app import TicketStatus
        statuses = TicketStatus.query.order_by(TicketStatus.order).all()
        return render_template('tickets/manage_statuses.html', statuses=statuses)

    @ticket_bp.route('/settings/custom-fields')
    @auth_required('manage_settings')
    def manage_custom_fields():
        """Manage custom fields"""
        from app import TicketCustomField
        fields = TicketCustomField.query.order_by(TicketCustomField.order).all()
        return render_template('tickets/manage_custom_fields.html', fields=fields)

    @ticket_bp.route('/settings/templates')
    @auth_required('manage_settings')
    def manage_templates():
        """Manage ticket templates"""
        from app import TicketTemplate
        templates = TicketTemplate.query.all()
        return render_template('tickets/manage_templates.html', templates=templates)

    @ticket_bp.route('/settings/sla')
    @auth_required('manage_settings')
    def manage_sla():
        """Manage SLA rules"""
        from app import TicketSLA
        sla_rules = TicketSLA.query.all()
        return render_template('tickets/manage_sla.html', sla_rules=sla_rules)

    # API endpoints for AJAX operations
    @ticket_bp.route('/api/category', methods=['POST'])
    @auth_required('manage_settings')
    def create_category():
        """Create new ticket category"""
        from app import TicketCategory

        data = request.get_json()
        category = TicketCategory(
            name=data['name'],
            description=data.get('description'),
            color=data.get('color', '#6c757d'),
            icon=data.get('icon', 'tag'),
            sla_hours=data.get('sla_hours', 24)
        )
        db.session.add(category)
        db.session.commit()

        return jsonify({'success': True, 'id': category.id})

    @ticket_bp.route('/api/priority', methods=['POST'])
    @auth_required('manage_settings')
    def create_priority():
        """Create new ticket priority"""
        from app import TicketPriority

        data = request.get_json()
        priority = TicketPriority(
            name=data['name'],
            level=data['level'],
            color=data.get('color', '#6c757d'),
            response_time_hours=data.get('response_time_hours', 24),
            resolution_time_hours=data.get('resolution_time_hours', 72)
        )
        db.session.add(priority)
        db.session.commit()

        return jsonify({'success': True, 'id': priority.id})

    @ticket_bp.route('/api/status', methods=['POST'])
    @auth_required('manage_settings')
    def create_status():
        """Create new ticket status"""
        from app import TicketStatus

        data = request.get_json()
        status = TicketStatus(
            name=data['name'],
            display_name=data.get('display_name', data['name']),
            description=data.get('description'),
            color=data.get('color', '#6c757d'),
            icon=data.get('icon', 'circle'),
            is_closed=data.get('is_closed', False),
            is_resolved=data.get('is_resolved', False),
            order=data.get('order', 0)
        )
        db.session.add(status)
        db.session.commit()

        return jsonify({'success': True, 'id': status.id})

    @ticket_bp.route('/api/custom-field', methods=['POST'])
    @auth_required('manage_settings')
    def create_custom_field():
        """Create new custom field"""
        from app import TicketCustomField

        data = request.get_json()
        field = TicketCustomField(
            name=data['name'],
            field_type=data['field_type'],
            options=json.dumps(data.get('options', [])) if data.get('options') else None,
            is_required=data.get('is_required', False),
            default_value=data.get('default_value'),
            help_text=data.get('help_text'),
            order=data.get('order', 0)
        )
        db.session.add(field)
        db.session.commit()

        return jsonify({'success': True, 'id': field.id})

    # UPDATE and DELETE endpoints
    @ticket_bp.route('/api/category/<int:id>', methods=['PUT'])
    @auth_required('manage_settings')
    def update_category(id):
        """Update ticket category"""
        from app import TicketCategory

        category = db.session.get(TicketCategory, id)
        if not category:
            return jsonify({'success': False, 'error': 'Category not found'}), 404

        data = request.get_json()
        category.name = data.get('name', category.name)
        category.description = data.get('description', category.description)
        category.color = data.get('color', category.color)
        category.icon = data.get('icon', category.icon)
        category.sla_hours = data.get('sla_hours', category.sla_hours)
        category.is_active = data.get('is_active', category.is_active)

        db.session.commit()
        return jsonify({'success': True})

    @ticket_bp.route('/api/category/<int:id>', methods=['DELETE'])
    @auth_required('manage_settings')
    def delete_category(id):
        """Delete ticket category"""
        from app import TicketCategory

        category = db.session.get(TicketCategory, id)
        if not category:
            return jsonify({'success': False, 'error': 'Category not found'}), 404

        db.session.delete(category)
        db.session.commit()
        return jsonify({'success': True})

    @ticket_bp.route('/api/priority/<int:id>', methods=['PUT'])
    @auth_required('manage_settings')
    def update_priority(id):
        """Update ticket priority"""
        from app import TicketPriority

        priority = db.session.get(TicketPriority, id)
        if not priority:
            return jsonify({'success': False, 'error': 'Priority not found'}), 404

        data = request.get_json()
        priority.name = data.get('name', priority.name)
        priority.level = data.get('level', priority.level)
        priority.color = data.get('color', priority.color)
        priority.response_time_hours = data.get('response_time_hours', priority.response_time_hours)
        priority.resolution_time_hours = data.get('resolution_time_hours', priority.resolution_time_hours)
        priority.auto_escalate = data.get('auto_escalate', priority.auto_escalate)
        priority.is_active = data.get('is_active', priority.is_active)

        db.session.commit()
        return jsonify({'success': True})

    @ticket_bp.route('/api/priority/<int:id>', methods=['DELETE'])
    @auth_required('manage_settings')
    def delete_priority(id):
        """Delete ticket priority"""
        from app import TicketPriority

        priority = db.session.get(TicketPriority, id)
        if not priority:
            return jsonify({'success': False, 'error': 'Priority not found'}), 404

        db.session.delete(priority)
        db.session.commit()
        return jsonify({'success': True})

    @ticket_bp.route('/api/status/<int:id>', methods=['PUT'])
    @auth_required('manage_settings')
    def update_status(id):
        """Update ticket status"""
        from app import TicketStatus

        status = db.session.get(TicketStatus, id)
        if not status:
            return jsonify({'success': False, 'error': 'Status not found'}), 404

        data = request.get_json()
        status.name = data.get('name', status.name)
        status.display_name = data.get('display_name', status.display_name)
        status.description = data.get('description', status.description)
        status.color = data.get('color', status.color)
        status.icon = data.get('icon', status.icon)
        status.is_closed = data.get('is_closed', status.is_closed)
        status.is_resolved = data.get('is_resolved', status.is_resolved)
        status.order = data.get('order', status.order)
        status.is_active = data.get('is_active', status.is_active)

        db.session.commit()
        return jsonify({'success': True})

    @ticket_bp.route('/api/status/<int:id>', methods=['DELETE'])
    @auth_required('manage_settings')
    def delete_status(id):
        """Delete ticket status"""
        from app import TicketStatus

        status = db.session.get(TicketStatus, id)
        if not status:
            return jsonify({'success': False, 'error': 'Status not found'}), 404

        db.session.delete(status)
        db.session.commit()
        return jsonify({'success': True})

    @ticket_bp.route('/api/custom-field/<int:id>', methods=['PUT'])
    @auth_required('manage_settings')
    def update_custom_field(id):
        """Update custom field"""
        from app import TicketCustomField

        field = db.session.get(TicketCustomField, id)
        if not field:
            return jsonify({'success': False, 'error': 'Field not found'}), 404

        data = request.get_json()
        field.name = data.get('name', field.name)
        field.field_type = data.get('field_type', field.field_type)
        field.options = json.dumps(data.get('options', [])) if data.get('options') else field.options
        field.is_required = data.get('is_required', field.is_required)
        field.default_value = data.get('default_value', field.default_value)
        field.help_text = data.get('help_text', field.help_text)
        field.order = data.get('order', field.order)
        field.is_active = data.get('is_active', field.is_active)

        db.session.commit()
        return jsonify({'success': True})

    @ticket_bp.route('/api/custom-field/<int:id>', methods=['DELETE'])
    @auth_required('manage_settings')
    def delete_custom_field(id):
        """Delete custom field"""
        from app import TicketCustomField

        field = db.session.get(TicketCustomField, id)
        if not field:
            return jsonify({'success': False, 'error': 'Field not found'}), 404

        db.session.delete(field)
        db.session.commit()
        return jsonify({'success': True})

    # ===== TEMPLATE API ENDPOINTS =====
    @ticket_bp.route('/api/template', methods=['POST'])
    @auth_required('manage_settings')
    def create_template():
        """Create new ticket template"""
        from app import TicketTemplate

        data = request.get_json()
        template = TicketTemplate(
            name=data['name'],
            description=data.get('description'),
            title_template=data.get('title_template', ''),
            description_template=data.get('description_template'),
            default_category=data.get('default_category'),
            default_priority=data.get('default_priority'),
            default_assignee_id=data.get('default_assignee_id'),
            is_active=data.get('is_active', True)
        )
        db.session.add(template)
        db.session.commit()

        return jsonify({'success': True, 'id': template.id})

    @ticket_bp.route('/api/template/<int:id>', methods=['PUT'])
    @auth_required('manage_settings')
    def update_template(id):
        """Update ticket template"""
        from app import TicketTemplate

        template = db.session.get(TicketTemplate, id)
        if not template:
            return jsonify({'success': False, 'error': 'Template not found'}), 404

        data = request.get_json()
        template.name = data.get('name', template.name)
        template.description = data.get('description', template.description)
        template.title_template = data.get('title_template', template.title_template)
        template.description_template = data.get('description_template', template.description_template)
        template.default_category = data.get('default_category', template.default_category)
        template.default_priority = data.get('default_priority', template.default_priority)
        template.default_assignee_id = data.get('default_assignee_id', template.default_assignee_id)
        template.is_active = data.get('is_active', template.is_active)

        db.session.commit()
        return jsonify({'success': True})

    @ticket_bp.route('/api/template/<int:id>', methods=['DELETE'])
    @auth_required('manage_settings')
    def delete_template(id):
        """Delete ticket template"""
        from app import TicketTemplate

        template = db.session.get(TicketTemplate, id)
        if not template:
            return jsonify({'success': False, 'error': 'Template not found'}), 404

        db.session.delete(template)
        db.session.commit()
        return jsonify({'success': True})

    # ===== SLA API ENDPOINTS =====
    @ticket_bp.route('/api/sla', methods=['POST'])
    @auth_required('manage_settings')
    def create_sla():
        """Create new SLA rule"""
        from app import TicketSLA

        data = request.get_json()
        sla = TicketSLA(
            name=data['name'],
            description=data.get('description'),
            priority_level=data.get('priority_level'),
            category_name=data.get('category_name'),
            first_response_hours=data.get('first_response_hours', 4),
            resolution_hours=data.get('resolution_hours', 24),
            warning_threshold_hours=data.get('warning_threshold_hours', 2),
            auto_escalate=data.get('auto_escalate', False),
            escalate_to_id=data.get('escalate_to_id'),
            is_active=data.get('is_active', True)
        )
        db.session.add(sla)
        db.session.commit()

        return jsonify({'success': True, 'id': sla.id})

    @ticket_bp.route('/api/sla/<int:id>', methods=['PUT'])
    @auth_required('manage_settings')
    def update_sla(id):
        """Update SLA rule"""
        from app import TicketSLA

        sla = db.session.get(TicketSLA, id)
        if not sla:
            return jsonify({'success': False, 'error': 'SLA rule not found'}), 404

        data = request.get_json()
        sla.name = data.get('name', sla.name)
        sla.description = data.get('description', sla.description)
        sla.priority_level = data.get('priority_level', sla.priority_level)
        sla.category_name = data.get('category_name', sla.category_name)
        sla.first_response_hours = data.get('first_response_hours', sla.first_response_hours)
        sla.resolution_hours = data.get('resolution_hours', sla.resolution_hours)
        sla.warning_threshold_hours = data.get('warning_threshold_hours', sla.warning_threshold_hours)
        sla.auto_escalate = data.get('auto_escalate', sla.auto_escalate)
        sla.escalate_to_id = data.get('escalate_to_id', sla.escalate_to_id)
        sla.is_active = data.get('is_active', sla.is_active)

        db.session.commit()
        return jsonify({'success': True})

    @ticket_bp.route('/api/sla/<int:id>', methods=['DELETE'])
    @auth_required('manage_settings')
    def delete_sla(id):
        """Delete SLA rule"""
        from app import TicketSLA

        sla = db.session.get(TicketSLA, id)
        if not sla:
            return jsonify({'success': False, 'error': 'SLA rule not found'}), 404

        db.session.delete(sla)
        db.session.commit()
        return jsonify({'success': True})

    # Register blueprint (check if not already registered)
    if 'tickets' not in app.blueprints:
        app.register_blueprint(ticket_bp)


# ═══════════════════════════════════════════════════════════════════════════
# ─── UTILITY FUNCTIONS ─────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

def calculate_sla_due_date(ticket, sla_rules):
    """Calculate SLA due date for a ticket"""
    applicable_sla = None

    for sla in sla_rules:
        if not sla.is_active:
            continue

        # Check if SLA applies to this ticket
        if sla.priority_level and ticket.priority != sla.priority_level:
            continue
        if sla.category_name and ticket.category != sla.category_name:
            continue

        applicable_sla = sla
        break

    if applicable_sla:
        return ticket.created_at + timedelta(hours=applicable_sla.resolution_hours)

    return ticket.created_at + timedelta(hours=24)  # Default 24h


def check_sla_breach(ticket, sla_rules):
    """Check if ticket is in SLA breach"""
    due_date = calculate_sla_due_date(ticket, sla_rules)

    if not ticket.resolved_at and datetime.utcnow() > due_date:
        return True, due_date

    return False, due_date


def auto_assign_ticket(ticket, categories):
    """Auto-assign ticket based on category"""
    category = next((c for c in categories if c.name == ticket.category), None)

    if category and category.default_assignee_id:
        ticket.assigned_to = category.default_assignee_id
        return True

    return False
