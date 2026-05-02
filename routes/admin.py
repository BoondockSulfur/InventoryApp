# -*- coding: utf-8 -*-
"""
Admin Routes Blueprint
All administrative routes for InventoryApp
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import login_required, current_user
from functools import wraps
import os
import subprocess
from datetime import datetime

# Create admin blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def require_admin(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Sie benötigen Admin-Rechte für diese Aktion.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def init_admin_routes(app, db):
    """Initialize admin routes with app and db context"""

    # Import models inside function to avoid circular imports
    from app import (
        Category, Location, Ticket, TicketResponse, Role, Permission,
        ModuleSetting, User, Item, Loan
    )
    from forms import CategoryForm, LocationForm, StatusForm, SettingsForm

    # ─── Categories Management ────────────────────────────────────────────

    @admin_bp.route('/categories')
    @login_required
    @require_admin
    def categories():
        """Admin: Manage categories"""
        categories = Category.query.all()
        return render_template('admin/categories.html', categories=categories)

    @admin_bp.route('/categories/add', methods=['GET', 'POST'])
    @login_required
    @require_admin
    def add_category():
        """Admin: Add new category"""
        form = CategoryForm()
        if form.validate_on_submit():
            category = Category(
                name=form.name.data,
                description=form.description.data,
                icon=form.icon.data,
                color=form.color.data
            )
            db.session.add(category)
            db.session.commit()
            flash('Kategorie erfolgreich erstellt!', 'success')
            return redirect(url_for('admin.categories'))
        return render_template('admin/add_category.html', form=form, title='Neue Kategorie')

    @admin_bp.route('/categories/<int:category_id>/edit', methods=['GET', 'POST'])
    @login_required
    @require_admin
    def edit_category(category_id):
        """Admin: Edit category"""
        category = db.session.get(Category, category_id)
        if not category:
            flash('Kategorie nicht gefunden.', 'danger')
            return redirect(url_for('admin.categories'))

        form = CategoryForm(obj=category)
        if form.validate_on_submit():
            category.name = form.name.data
            category.description = form.description.data
            category.icon = form.icon.data
            category.color = form.color.data
            db.session.commit()
            flash('Kategorie aktualisiert!', 'success')
            return redirect(url_for('admin.categories'))
        return render_template('admin/edit_category.html', form=form, title='Kategorie bearbeiten', category=category)

    @admin_bp.route('/categories/<int:category_id>/delete', methods=['POST'])
    @login_required
    @require_admin
    def delete_category(category_id):
        """Admin: Delete category"""
        category = db.session.get(Category, category_id)
        if not category:
            flash('Kategorie nicht gefunden.', 'danger')
            return redirect(url_for('admin.categories'))

        # Check if category has items
        items_count = Item.query.filter_by(category_id=category_id).count()
        if items_count > 0:
            flash(f'Kategorie kann nicht gelöscht werden - {items_count} Artikel verwenden diese Kategorie.', 'danger')
            return redirect(url_for('admin.categories'))

        db.session.delete(category)
        db.session.commit()
        flash('Kategorie gelöscht!', 'success')
        return redirect(url_for('admin.categories'))

    # ─── Locations Management ─────────────────────────────────────────────

    @admin_bp.route('/locations')
    @login_required
    @require_admin
    def locations():
        """Admin: Manage locations"""
        locations = Location.query.all()

        # Build tree structure
        def build_tree(parent_id=None, level=0):
            locs = [loc for loc in locations if loc.parent_id == parent_id]
            tree = []
            for loc in sorted(locs, key=lambda x: x.name):
                # Count items for this location
                item_count = Item.query.filter_by(location_id=loc.id).count()
                tree.append({'location': loc, 'level': level, 'item_count': item_count})
                tree.extend(build_tree(loc.id, level + 1))
            return tree

        location_tree = build_tree()
        return render_template('admin/locations.html', locations=location_tree)

    @admin_bp.route('/locations/add', methods=['GET', 'POST'])
    @login_required
    @require_admin
    def add_location():
        """Admin: Add new location"""
        form = LocationForm()

        # Populate parent choices
        locations = Location.query.all()
        form.parent_id.choices = [(0, '(Kein Übergeordneter Standort)')] + [
            (loc.id, loc.name) for loc in sorted(locations, key=lambda x: x.name)
        ]

        if form.validate_on_submit():
            parent_id = form.parent_id.data if form.parent_id.data != 0 else None
            location = Location(
                name=form.name.data,
                parent_id=parent_id
            )
            db.session.add(location)
            db.session.commit()
            flash('Standort erfolgreich erstellt!', 'success')
            return redirect(url_for('admin.locations'))

        return render_template('admin/add_location.html', form=form, title='Neuer Standort')

    @admin_bp.route('/locations/<int:location_id>/edit', methods=['GET', 'POST'])
    @login_required
    @require_admin
    def edit_location(location_id):
        """Admin: Edit location"""
        location = db.session.get(Location, location_id)
        if not location:
            flash('Standort nicht gefunden.', 'danger')
            return redirect(url_for('admin.locations'))

        form = LocationForm(obj=location)

        # Populate parent choices (exclude self and children to prevent loops)
        def get_child_ids(loc_id):
            children = Location.query.filter_by(parent_id=loc_id).all()
            child_ids = [loc_id]
            for child in children:
                child_ids.extend(get_child_ids(child.id))
            return child_ids

        excluded_ids = get_child_ids(location_id)
        locations = Location.query.filter(~Location.id.in_(excluded_ids)).all()
        form.parent_id.choices = [(0, '(Kein Übergeordneter Standort)')] + [
            (loc.id, loc.name) for loc in sorted(locations, key=lambda x: x.name)
        ]

        if form.validate_on_submit():
            location.name = form.name.data
            location.parent_id = form.parent_id.data if form.parent_id.data != 0 else None
            db.session.commit()
            flash('Standort aktualisiert!', 'success')
            return redirect(url_for('admin.locations'))

        # Set current parent
        if location.parent_id:
            form.parent_id.data = location.parent_id
        else:
            form.parent_id.data = 0

        return render_template('admin/edit_location.html', form=form, title='Standort bearbeiten', location=location)

    @admin_bp.route('/locations/<int:location_id>/delete', methods=['POST'])
    @login_required
    @require_admin
    def delete_location(location_id):
        """Admin: Delete location"""
        location = db.session.get(Location, location_id)
        if not location:
            flash('Standort nicht gefunden.', 'danger')
            return redirect(url_for('admin.locations'))

        # Check if location has items
        items_count = Item.query.filter_by(location_id=location_id).count()
        if items_count > 0:
            flash(f'Standort kann nicht gelöscht werden - {items_count} Artikel befinden sich an diesem Standort.', 'danger')
            return redirect(url_for('admin.locations'))

        # Check if location has children
        children_count = Location.query.filter_by(parent_id=location_id).count()
        if children_count > 0:
            flash(f'Standort kann nicht gelöscht werden - {children_count} Unterstandorte existieren.', 'danger')
            return redirect(url_for('admin.locations'))

        db.session.delete(location)
        db.session.commit()
        flash('Standort gelöscht!', 'success')
        return redirect(url_for('admin.locations'))

    # ─── Tickets Management ───────────────────────────────────────────────

    @admin_bp.route('/tickets', methods=['GET'])
    @login_required
    @require_admin
    def tickets():
        """Admin: View all tickets"""
        status_filter = request.args.get('status', 'all')

        query = Ticket.query
        if status_filter != 'all':
            query = query.filter_by(status=status_filter)

        tickets = query.order_by(Ticket.created_at.desc()).all()

        # Get response counts
        for ticket in tickets:
            ticket.response_count = TicketResponse.query.filter_by(ticket_id=ticket.id).count()

        return render_template('admin_tickets.html', tickets=tickets, status_filter=status_filter)

    @admin_bp.route('/ticket/<int:ticket_id>/status', methods=['POST'])
    @login_required
    @require_admin
    def update_ticket_status(ticket_id):
        """Admin: Update ticket status"""
        ticket = db.session.get(Ticket, ticket_id)
        if not ticket:
            return jsonify({'success': False, 'error': 'Ticket nicht gefunden'}), 404

        new_status = request.json.get('status')
        if new_status not in ['open', 'in_progress', 'closed']:
            return jsonify({'success': False, 'error': 'Ungültiger Status'}), 400

        ticket.status = new_status
        ticket.updated_at = datetime.utcnow()
        db.session.commit()

        return jsonify({'success': True})

    # ─── Roles Management ─────────────────────────────────────────────────

    @admin_bp.route('/roles')
    @login_required
    @require_admin
    def roles():
        """Admin: Manage roles"""
        roles = Role.query.all()
        permissions = Permission.query.all()
        return render_template('admin_roles.html', roles=roles, permissions=permissions)

    @admin_bp.route('/roles/add', methods=['POST'])
    @login_required
    @require_admin
    def add_role():
        """Admin: Add new role"""
        role_name = request.form.get('name')
        if not role_name:
            flash('Rollenname erforderlich.', 'danger')
            return redirect(url_for('admin.roles'))

        if Role.query.get(role_name):
            flash('Rolle existiert bereits.', 'danger')
            return redirect(url_for('admin.roles'))

        role = Role(name=role_name)
        db.session.add(role)
        db.session.commit()
        flash('Rolle erstellt!', 'success')
        return redirect(url_for('admin.roles'))

    @admin_bp.route('/role/<role_name>/edit', methods=['GET','POST'])
    @login_required
    @require_admin
    def edit_role(role_name):
        """Admin: Edit role permissions"""
        role = db.session.get(Role, role_name)
        if not role:
            flash('Rolle nicht gefunden.', 'danger')
            return redirect(url_for('admin.roles'))

        if request.method == 'POST':
            # Clear existing permissions
            role.permissions = []

            # Add selected permissions
            permission_ids = request.form.getlist('permissions')
            for perm_name in permission_ids:
                perm = db.session.get(Permission, perm_name)
                if perm:
                    role.permissions.append(perm)

            db.session.commit()
            flash('Rollenberechtigungen aktualisiert!', 'success')
            return redirect(url_for('admin.roles'))

        permissions = Permission.query.all()
        return render_template('edit_role.html', role=role, permissions=permissions)

    @admin_bp.route('/roles/<role_name>/delete', methods=['POST'])
    @login_required
    @require_admin
    def delete_role(role_name):
        """Admin: Delete role"""
        # Protect system roles
        if role_name in ['admin', 'verwaltung', 'mitarbeiter', 'kunde']:
            flash('System-Rollen können nicht gelöscht werden.', 'danger')
            return redirect(url_for('admin.roles'))

        role = db.session.get(Role, role_name)
        if not role:
            flash('Rolle nicht gefunden.', 'danger')
            return redirect(url_for('admin.roles'))

        # Check if users have this role
        users_count = User.query.filter_by(role=role_name).count()
        if users_count > 0:
            flash(f'Rolle kann nicht gelöscht werden - {users_count} Benutzer haben diese Rolle.', 'danger')
            return redirect(url_for('admin.roles'))

        db.session.delete(role)
        db.session.commit()
        flash('Rolle gelöscht!', 'success')
        return redirect(url_for('admin.roles'))

    # ─── System Management ────────────────────────────────────────────────

    @admin_bp.route('/system-logs')
    @login_required
    @require_admin
    def system_logs():
        """Admin: View system logs"""
        return render_template('admin/system_logs.html')

    # NOTE: admin.settings route is now in app.py (admin_settings function)
    # The route was too complex to migrate to blueprint, so it stays in app.py

    @admin_bp.route('/setup')
    @login_required
    @require_admin
    def setup():
        """Admin: Setup wizard"""
        return render_template('initial_setup.html')

    @admin_bp.route('/check-updates')
    @login_required
    @require_admin
    def check_updates():
        """Admin: Check for updates"""
        try:
            result = subprocess.run(
                ['git', 'fetch', 'origin'],
                capture_output=True,
                text=True,
                timeout=10
            )

            result = subprocess.run(
                ['git', 'rev-list', '--count', 'HEAD..origin/master'],
                capture_output=True,
                text=True,
                timeout=10
            )

            commits_behind = int(result.stdout.strip()) if result.returncode == 0 else 0

            return jsonify({
                'success': True,
                'updates_available': commits_behind > 0,
                'commits_behind': commits_behind
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @admin_bp.route('/apply-update', methods=['POST'])
    @login_required
    @require_admin
    def apply_update():
        """Admin: Apply system update"""
        try:
            # Pull latest changes
            result = subprocess.run(
                ['git', 'pull', 'origin', 'master'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return jsonify({'success': False, 'error': result.stderr})

            # Install dependencies
            subprocess.run(
                ['pip', 'install', '-r', 'requirements.txt'],
                capture_output=True,
                timeout=60
            )

            return jsonify({'success': True, 'message': 'Update erfolgreich. Bitte System neu starten.'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    @admin_bp.route('/restart-system', methods=['POST'])
    @login_required
    @require_admin
    def restart_system():
        """Admin: Restart system"""
        try:
            # Trigger restart (implementation depends on deployment)
            subprocess.Popen(['sudo', 'systemctl', 'restart', 'inventoryapp'])
            return jsonify({'success': True, 'message': 'System wird neu gestartet...'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})

    # Register blueprint
    app.register_blueprint(admin_bp)
    app.logger.info("✅ Admin routes blueprint registered")
