# -*- coding: utf-8 -*-
"""
API Routes for InventoryApp v2.3.0
Additional routes for new features: GraphQL, Analytics, Reporting, WebSocket
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user
from datetime import datetime, timedelta

# Create blueprints
api_bp = Blueprint('api', __name__, url_prefix='/api')
analytics_bp = Blueprint('analytics', __name__, url_prefix='/analytics')
reports_bp = Blueprint('reports_bp', __name__, url_prefix='/reports')


def init_api_routes(app, db, GRAPHQL_AVAILABLE, PLOTLY_AVAILABLE, socketio):
    """Initialize all API routes"""

    from app import Item, Category, Location, Loan, User

    # Helper functions for model serialization (avoids circular imports with to_dict methods)
    def serialize_item(item):
        """Serialize Item model to dictionary"""
        return {
            'id': item.id,
            'name': item.name,
            'note': item.note,
            'serial': item.serial,
            'category_id': item.category_id,
            'category': item.category_rel.name if item.category_rel else (item.category if hasattr(item, 'category') else None),
            'location_id': item.location_id,
            'location': item.location_rel.name if item.location_rel else (item.location if hasattr(item, 'location') else None),
            'is_borrowed': item.is_borrowed,
            'defective': item.defective,
            'created_at': item.created_at.isoformat() if hasattr(item, 'created_at') and item.created_at else None
        }

    def serialize_loan(loan):
        """Serialize Loan model to dictionary"""
        return {
            'id': loan.id,
            'item_id': loan.item_id,
            'item_name': loan.item.name if loan.item else None,
            'borrower_id': loan.borrower_id,
            'borrower_name': loan.borrower.username if loan.borrower else None,
            'loan_date': loan.loan_date.isoformat() if loan.loan_date else None,
            'due_date': loan.due_date.isoformat() if loan.due_date else None,
            'return_date': loan.return_date.isoformat() if loan.return_date else None,
            'is_overdue': loan.due_date < datetime.utcnow().date() if loan.due_date and not loan.return_date else False
        }

    # ─── GraphQL API ──────────────────────────────────────────────────

    if GRAPHQL_AVAILABLE:
        try:
            from flask_graphql import GraphQLView
            from graphql_schema import schema

            if schema:
                app.add_url_rule(
                    '/graphql',
                    view_func=GraphQLView.as_view(
                        'graphql',
                        schema=schema,
                        graphiql=True  # Enable GraphiQL IDE
                    )
                )
                app.logger.info("✅ GraphQL API initialized at /graphql")
        except Exception as e:
            app.logger.error(f"GraphQL initialization failed: {e}")

    # ─── Analytics Routes ─────────────────────────────────────────────

    @analytics_bp.route('/')
    @login_required
    def analytics_dashboard():
        """Analytics dashboard page"""
        if not PLOTLY_AVAILABLE:
            return "Analytics not available - Plotly not installed", 503

        from analytics import generate_dashboard_charts

        charts = generate_dashboard_charts(db, Item, Category, Location, Loan, User)

        return render_template('analytics/dashboard.html', charts=charts)

    @analytics_bp.route('/api/charts')
    @login_required
    def get_charts_data():
        """API endpoint to get all charts data as JSON"""
        if not PLOTLY_AVAILABLE:
            return jsonify({'error': 'Analytics not available'}), 503

        from analytics import generate_dashboard_charts

        charts = generate_dashboard_charts(db, Item, Category, Location, Loan, User)
        return jsonify(charts)

    @analytics_bp.route('/api/chart/<chart_type>')
    @login_required
    def get_single_chart(chart_type):
        """API endpoint to get a single chart"""
        if not PLOTLY_AVAILABLE:
            return jsonify({'error': 'Analytics not available'}), 503

        from analytics import (
            generate_inventory_overview_chart,
            generate_loan_timeline_chart,
            generate_item_status_pie_chart,
            generate_location_heatmap,
            generate_overdue_loans_chart
        )

        chart_functions = {
            'inventory_overview': lambda: generate_inventory_overview_chart(db, Item, Category),
            'loan_timeline': lambda: generate_loan_timeline_chart(db, Loan),
            'item_status': lambda: generate_item_status_pie_chart(db, Item),
            'location_heatmap': lambda: generate_location_heatmap(db, Item, Location),
            'overdue_loans': lambda: generate_overdue_loans_chart(db, Loan, User)
        }

        if chart_type not in chart_functions:
            return jsonify({'error': 'Invalid chart type'}), 400

        chart_data = chart_functions[chart_type]()
        return jsonify({'chart': chart_data})

    # ─── Reporting Routes ─────────────────────────────────────────────

    @reports_bp.route('/generate')
    @login_required
    def generate_report_page():
        """Report generation page"""
        # TODO: Add permission check when circular import is fully resolved
        categories = Category.query.all()
        locations = Location.query.all()
        return render_template('reports/generate.html',
                             categories=categories,
                             locations=locations)

    @reports_bp.route('/inventory')
    @login_required
    def inventory_report():
        """Generate inventory report"""
        from reporting import get_report_generator

        format_type = request.args.get('format', 'csv')
        filters = {
            'category_id': request.args.get('category_id', type=int),
            'location_id': request.args.get('location_id', type=int),
            'is_borrowed': request.args.get('is_borrowed', type=lambda x: x.lower() == 'true') if request.args.get('is_borrowed') else None,
            'defective': request.args.get('defective', type=lambda x: x.lower() == 'true') if request.args.get('defective') else None
        }

        # Remove None values
        filters = {k: v for k, v in filters.items() if v is not None}

        try:
            report_gen = get_report_generator(db)
            return report_gen.generate_inventory_report(format=format_type, filters=filters)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            app.logger.error(f"Report generation error: {e}")
            return jsonify({'error': 'Report generation failed'}), 500

    @reports_bp.route('/loans')
    @login_required
    def loans_report():
        """Generate loans report"""
        from reporting import get_report_generator

        format_type = request.args.get('format', 'csv')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')

        if date_from:
            date_from = datetime.fromisoformat(date_from)
        if date_to:
            date_to = datetime.fromisoformat(date_to)

        try:
            report_gen = get_report_generator(db)
            return report_gen.generate_loan_report(format=format_type,
                                                  date_from=date_from,
                                                  date_to=date_to)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            app.logger.error(f"Report generation error: {e}")
            return jsonify({'error': 'Report generation failed'}), 500

    # ─── Mobile API Routes ────────────────────────────────────────────

    @api_bp.route('/items')
    @login_required
    def api_items_list():
        """API: Get all items (for mobile app)"""
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('q', '')

        query = Item.query

        if search:
            query = query.filter(
                db.or_(
                    Item.name.ilike(f'%{search}%'),
                    Item.serial.ilike(f'%{search}%'),
                    Item.note.ilike(f'%{search}%') if Item.note else False
                )
            )

        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        items = pagination.items

        return jsonify({
            'items': [serialize_item(item) for item in items],
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'pages': pagination.pages
        })

    @api_bp.route('/items/<int:id>')
    @login_required
    def api_item_detail(id):
        """API: Get single item"""
        item = db.session.get(Item, id)
        if not item:
            return jsonify({'error': 'Item not found'}), 404

        return jsonify(serialize_item(item))

    @api_bp.route('/items/barcode/<barcode>')
    @login_required
    def api_item_by_barcode(barcode):
        """API: Get item by barcode/serial"""
        item = Item.query.filter_by(serial=barcode).first()
        if not item:
            return jsonify({'error': 'Item not found'}), 404

        return jsonify(serialize_item(item))

    @api_bp.route('/loans/active')
    @login_required
    def api_active_loans():
        """API: Get active loans"""
        loans = Loan.query.filter(Loan.return_date.is_(None)).all()

        return jsonify({
            'loans': [serialize_loan(loan) for loan in loans]
        })

    @api_bp.route('/loans/overdue')
    @login_required
    def api_overdue_loans():
        """API: Get overdue loans"""
        loans = Loan.query.filter(
            Loan.return_date.is_(None),
            Loan.due_date < datetime.utcnow()
        ).all()

        return jsonify({
            'loans': [serialize_loan(loan) for loan in loans]
        })

    @api_bp.route('/categories')
    @login_required
    def api_categories():
        """API: Get all categories"""
        categories = Category.query.all()
        return jsonify({
            'categories': [{'id': c.id, 'name': c.name} for c in categories]
        })

    @api_bp.route('/locations')
    @login_required
    def api_locations():
        """API: Get all locations"""
        locations = Location.query.all()
        return jsonify({
            'locations': [{'id': l.id, 'name': l.name} for l in locations]
        })

    @api_bp.route('/auth/me')
    @login_required
    def api_current_user():
        """API: Get current user info"""
        return jsonify({
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'role': current_user.role
        })

    # ─── Language Switch Route ────────────────────────────────────────

    @app.route('/set-language/<lang>')
    @login_required
    def set_language(lang):
        """Switch language"""
        from flask import session, redirect, url_for

        if lang in app.config['LANGUAGES']:
            session['language'] = lang

            # Also save to user preferences if enabled
            from app import ModuleSetting

            user_lang = db.session.query(ModuleSetting).filter_by(
                key='user_language',
                user_id=current_user.id
            ).first()

            if user_lang:
                user_lang.value = lang
            else:
                user_lang = ModuleSetting(
                    key='user_language',
                    value=lang,
                    user_id=current_user.id
                )
                db.session.add(user_lang)

            db.session.commit()

        return redirect(request.referrer or url_for('dashboard'))

    # Register blueprints
    app.register_blueprint(api_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(reports_bp)

    app.logger.info("✅ API routes initialized")


# DEPRECATED: add_to_dict_methods is no longer needed
# Serialization is now handled by serialize_item() and serialize_loan() functions
# inside init_api_routes() to avoid circular import issues
