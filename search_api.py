"""
Search API Routes
Endpoints for Elasticsearch-powered advanced search
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

search_api = Blueprint('search_api', __name__, url_prefix='/api/search')


@search_api.route('/items', methods=['GET'])
@login_required
def search_items():
    """
    Advanced search for items using Elasticsearch

    Query parameters:
        - q: Search query
        - category: Filter by category
        - status: Filter by status
        - location: Filter by location
        - date_from: Filter by creation date (from)
        - date_to: Filter by creation date (to)
        - sort: Sort order (relevance, name_asc, name_desc, date_asc, date_desc)
        - page: Page number (default: 1)
        - per_page: Results per page (default: 20)

    Returns:
        JSON with search results and pagination info
    """
    try:
        from elasticsearch_service import es_service

        query = request.args.get('q', '')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Build filters
        filters = {}
        if request.args.get('category'):
            filters['category'] = request.args.get('category')
        if request.args.get('status'):
            filters['status'] = request.args.get('status')
        if request.args.get('location'):
            filters['location'] = request.args.get('location')
        if request.args.get('date_from'):
            filters['date_from'] = request.args.get('date_from')
        if request.args.get('date_to'):
            filters['date_to'] = request.args.get('date_to')

        # Perform search
        result = es_service.search_items(
            query=query,
            filters=filters,
            page=page,
            per_page=per_page
        )

        return jsonify({
            'success': True,
            'results': result['results'],
            'total': result['total'],
            'page': result['page'],
            'per_page': result['per_page'],
            'pages': result.get('pages', 1)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@search_api.route('/tickets', methods=['GET'])
@login_required
def search_tickets():
    """Advanced search for tickets using Elasticsearch"""
    try:
        from elasticsearch_service import es_service

        query = request.args.get('q', '')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Build filters
        filters = {}
        if request.args.get('category'):
            filters['category'] = request.args.get('category')
        if request.args.get('priority'):
            filters['priority'] = request.args.get('priority')
        if request.args.get('status'):
            filters['status'] = request.args.get('status')
        if request.args.get('assigned_to'):
            filters['assigned_to'] = request.args.get('assigned_to')

        # Perform search
        result = es_service.search_tickets(
            query=query,
            filters=filters,
            page=page,
            per_page=per_page
        )

        return jsonify({
            'success': True,
            'results': result['results'],
            'total': result['total'],
            'page': result['page'],
            'per_page': result['per_page'],
            'pages': result.get('pages', 1)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@search_api.route('/suggestions', methods=['GET'])
@login_required
def get_search_suggestions():
    """
    Get search suggestions based on query

    Query parameters:
        - q: Partial search query

    Returns:
        JSON with suggestions
    """
    try:
        from app import Item, db

        query = request.args.get('q', '')

        if len(query) < 2:
            return jsonify({
                'success': True,
                'suggestions': []
            })

        # Get suggestions from database (could also use Elasticsearch)
        items = Item.query.filter(
            db.or_(
                Item.name.ilike(f'%{query}%'),
                Item.serial_number.ilike(f'%{query}%')
            )
        ).limit(10).all()

        suggestions = [
            {
                'text': item.name,
                'type': 'item',
                'id': item.id
            }
            for item in items
        ]

        return jsonify({
            'success': True,
            'suggestions': suggestions
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@search_api.route('/reindex', methods=['POST'])
@login_required
def reindex_all():
    """
    Reindex all entities in Elasticsearch
    (Admin only)
    """
    try:
        # Check if user is admin
        if not current_user.role == 'admin':
            return jsonify({
                'success': False,
                'error': 'Admin access required'
            }), 403

        from elasticsearch_service import es_service
        from app import db

        result = es_service.reindex_all(db)

        if result:
            return jsonify({
                'success': True,
                'message': 'Reindexing completed successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Reindexing failed'
            }), 500

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@search_api.route('/ai/recommendations', methods=['GET'])
@login_required
def get_ai_recommendations():
    """
    Get AI-powered recommendations for the current user

    Returns:
        JSON with recommended items
    """
    try:
        from ml_service import ml_service
        from app import Item, Loan, db

        # Get all items and loans
        items = Item.query.all()
        loans = Loan.query.all()

        # Generate recommendations
        recommendations = ml_service.generate_recommendations(
            user=current_user,
            items=items,
            loans=loans,
            limit=5
        )

        # Format recommendations
        results = [
            {
                'id': item.id,
                'name': item.name,
                'description': item.description,
                'category': item.category if hasattr(item, 'category') else None,
                'image_url': item.image_url if hasattr(item, 'image_url') else None
            }
            for item in recommendations
        ]

        return jsonify({
            'success': True,
            'recommendations': results
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@search_api.route('/ai/predict-category', methods=['POST'])
@login_required
def predict_category():
    """
    Predict category for an item using AI

    Request body:
        {
            "name": "Item name",
            "description": "Item description"
        }

    Returns:
        JSON with predicted category and confidence
    """
    try:
        from ml_service import ml_service

        data = request.get_json()
        name = data.get('name', '')
        description = data.get('description', '')

        if not name:
            return jsonify({
                'success': False,
                'error': 'Item name is required'
            }), 400

        prediction = ml_service.predict_category(name, description)

        return jsonify({
            'success': True,
            **prediction
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@search_api.route('/ai/train-categorizer', methods=['POST'])
@login_required
def train_categorizer():
    """
    Train the category prediction model
    (Admin only)
    """
    try:
        # Check if user is admin
        if not current_user.role == 'admin':
            return jsonify({
                'success': False,
                'error': 'Admin access required'
            }), 403

        from ml_service import ml_service
        from app import Item

        # Get all items with categories
        items = Item.query.filter(Item.category.isnot(None)).all()

        result = ml_service.train_categorizer(items)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@search_api.route('/ai/maintenance-predictions', methods=['GET'])
@login_required
def get_maintenance_predictions():
    """
    Get predictive maintenance alerts

    Returns:
        JSON with items that may need maintenance soon
    """
    try:
        from ml_service import ml_service
        from app import Item, db

        # Get all items and maintenance history
        items = Item.query.all()

        # Get maintenance history (assuming you have a MaintenanceLog model)
        # For now, we'll use an empty list
        maintenance_history = []

        predictions = ml_service.predict_maintenance(items, maintenance_history)

        return jsonify({
            'success': True,
            'predictions': predictions
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@search_api.route('/ai/usage-patterns', methods=['GET'])
@login_required
def analyze_usage_patterns():
    """
    Analyze usage patterns

    Returns:
        JSON with usage insights
    """
    try:
        from ml_service import ml_service
        from app import Item, Loan

        items = Item.query.all()
        loans = Loan.query.all()

        analysis = ml_service.analyze_usage_patterns(items, loans)

        return jsonify({
            'success': True,
            **analysis
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
