"""
Elasticsearch Service for Advanced Search
Handles indexing and searching of inventory items, tickets, and other entities
"""

import os
import logging
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from datetime import datetime

logger = logging.getLogger(__name__)


class ElasticsearchService:
    """Service for managing Elasticsearch operations"""

    def __init__(self, app=None):
        self.es = None
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize Elasticsearch connection"""
        self.app = app
        es_url = os.environ.get('ELASTICSEARCH_URL', 'http://localhost:9200')

        try:
            self.es = Elasticsearch([es_url], request_timeout=30)
            if self.es.ping():
                logger.info(f"Connected to Elasticsearch at {es_url}")
                self._create_indices()
            else:
                logger.warning("Could not connect to Elasticsearch")
        except Exception as e:
            logger.error(f"Elasticsearch connection error: {e}")
            self.es = None

    def _create_indices(self):
        """Create Elasticsearch indices for different entity types"""
        indices = {
            'items': {
                'mappings': {
                    'properties': {
                        'id': {'type': 'integer'},
                        'name': {'type': 'text', 'analyzer': 'standard'},
                        'description': {'type': 'text', 'analyzer': 'standard'},
                        'category': {'type': 'keyword'},
                        'serial_number': {'type': 'keyword'},
                        'asset_tag': {'type': 'keyword'},
                        'location': {'type': 'text'},
                        'status': {'type': 'keyword'},
                        'purchase_date': {'type': 'date'},
                        'warranty_end': {'type': 'date'},
                        'created_at': {'type': 'date'},
                        'updated_at': {'type': 'date'},
                        'tags': {'type': 'keyword'},
                    }
                }
            },
            'tickets': {
                'mappings': {
                    'properties': {
                        'id': {'type': 'integer'},
                        'title': {'type': 'text', 'analyzer': 'standard'},
                        'description': {'type': 'text', 'analyzer': 'standard'},
                        'category': {'type': 'keyword'},
                        'priority': {'type': 'keyword'},
                        'status': {'type': 'keyword'},
                        'assigned_to': {'type': 'keyword'},
                        'created_by': {'type': 'keyword'},
                        'created_at': {'type': 'date'},
                        'updated_at': {'type': 'date'},
                        'due_date': {'type': 'date'},
                    }
                }
            },
            'audit_logs': {
                'mappings': {
                    'properties': {
                        'id': {'type': 'integer'},
                        'action': {'type': 'keyword'},
                        'entity_type': {'type': 'keyword'},
                        'entity_id': {'type': 'integer'},
                        'user': {'type': 'keyword'},
                        'changes': {'type': 'object'},
                        'timestamp': {'type': 'date'},
                        'ip_address': {'type': 'ip'},
                    }
                }
            }
        }

        if not self.es:
            return

        for index_name, index_config in indices.items():
            try:
                if not self.es.indices.exists(index=index_name):
                    self.es.indices.create(index=index_name, body=index_config)
                    logger.info(f"Created index: {index_name}")
            except Exception as e:
                logger.error(f"Error creating index {index_name}: {e}")

    def index_item(self, item):
        """Index a single item"""
        if not self.es:
            return False

        try:
            doc = {
                'id': item.id,
                'name': item.name,
                'description': item.description or '',
                'category': item.category if hasattr(item, 'category') else '',
                'serial_number': item.serial_number or '',
                'asset_tag': item.asset_tag or '',
                'location': item.location or '',
                'status': item.status if hasattr(item, 'status') else 'available',
                'purchase_date': item.purchase_date.isoformat() if hasattr(item, 'purchase_date') and item.purchase_date else None,
                'warranty_end': item.warranty_end.isoformat() if hasattr(item, 'warranty_end') and item.warranty_end else None,
                'created_at': item.created_at.isoformat() if hasattr(item, 'created_at') else datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat(),
            }

            self.es.index(index='items', id=item.id, document=doc)
            return True
        except Exception as e:
            logger.error(f"Error indexing item {item.id}: {e}")
            return False

    def index_ticket(self, ticket):
        """Index a single ticket"""
        if not self.es:
            return False

        try:
            doc = {
                'id': ticket.id,
                'title': ticket.title,
                'description': ticket.description or '',
                'category': ticket.category.name if ticket.category else '',
                'priority': str(ticket.priority),
                'status': ticket.status.name if ticket.status else '',
                'assigned_to': ticket.assigned_to.username if ticket.assigned_to else '',
                'created_by': ticket.created_by.username if ticket.created_by else '',
                'created_at': ticket.created_at.isoformat(),
                'updated_at': datetime.utcnow().isoformat(),
                'due_date': ticket.due_date.isoformat() if ticket.due_date else None,
            }

            self.es.index(index='tickets', id=ticket.id, document=doc)
            return True
        except Exception as e:
            logger.error(f"Error indexing ticket {ticket.id}: {e}")
            return False

    def index_audit_log(self, log):
        """Index an audit log entry"""
        if not self.es:
            return False

        try:
            doc = {
                'id': log.id,
                'action': log.action,
                'entity_type': log.entity_type,
                'entity_id': log.entity_id,
                'user': log.user.username if log.user else 'system',
                'changes': log.changes or {},
                'timestamp': log.timestamp.isoformat(),
                'ip_address': log.ip_address or '',
            }

            self.es.index(index='audit_logs', id=log.id, document=doc)
            return True
        except Exception as e:
            logger.error(f"Error indexing audit log {log.id}: {e}")
            return False

    def bulk_index_items(self, items):
        """Bulk index multiple items"""
        if not self.es:
            return False

        try:
            actions = []
            for item in items:
                doc = {
                    '_index': 'items',
                    '_id': item.id,
                    '_source': {
                        'id': item.id,
                        'name': item.name,
                        'description': item.description or '',
                        'category': item.category if hasattr(item, 'category') else '',
                        'serial_number': item.serial_number or '',
                        'asset_tag': item.asset_tag or '',
                        'location': item.location or '',
                        'status': item.status if hasattr(item, 'status') else 'available',
                        'created_at': item.created_at.isoformat() if hasattr(item, 'created_at') else datetime.utcnow().isoformat(),
                        'updated_at': datetime.utcnow().isoformat(),
                    }
                }
                actions.append(doc)

            if actions:
                bulk(self.es, actions)
                logger.info(f"Bulk indexed {len(actions)} items")
                return True
        except Exception as e:
            logger.error(f"Error bulk indexing items: {e}")
            return False

    def search_items(self, query, filters=None, page=1, per_page=20):
        """
        Advanced search for items

        Args:
            query: Search query string
            filters: Dict of filters (category, status, location, etc.)
            page: Page number
            per_page: Results per page

        Returns:
            Dict with results and pagination info
        """
        if not self.es:
            return {'results': [], 'total': 0, 'page': page, 'per_page': per_page}

        try:
            # Build the search query
            must_clauses = []

            if query:
                must_clauses.append({
                    'multi_match': {
                        'query': query,
                        'fields': ['name^3', 'description^2', 'serial_number^2', 'asset_tag^2', 'location'],
                        'type': 'best_fields',
                        'fuzziness': 'AUTO'
                    }
                })

            # Add filters
            filter_clauses = []
            if filters:
                if filters.get('category'):
                    filter_clauses.append({'term': {'category': filters['category']}})
                if filters.get('status'):
                    filter_clauses.append({'term': {'status': filters['status']}})
                if filters.get('location'):
                    filter_clauses.append({'match': {'location': filters['location']}})
                if filters.get('date_from'):
                    filter_clauses.append({'range': {'created_at': {'gte': filters['date_from']}}})
                if filters.get('date_to'):
                    filter_clauses.append({'range': {'created_at': {'lte': filters['date_to']}}})

            # Construct the query
            body = {
                'query': {
                    'bool': {
                        'must': must_clauses if must_clauses else [{'match_all': {}}],
                        'filter': filter_clauses
                    }
                },
                'from': (page - 1) * per_page,
                'size': per_page,
                'sort': [{'_score': 'desc'}, {'updated_at': 'desc'}]
            }

            response = self.es.search(index='items', body=body)

            results = [hit['_source'] for hit in response['hits']['hits']]
            total = response['hits']['total']['value']

            return {
                'results': results,
                'total': total,
                'page': page,
                'per_page': per_page,
                'pages': (total + per_page - 1) // per_page
            }
        except Exception as e:
            logger.error(f"Error searching items: {e}")
            return {'results': [], 'total': 0, 'page': page, 'per_page': per_page}

    def search_tickets(self, query, filters=None, page=1, per_page=20):
        """Advanced search for tickets"""
        if not self.es:
            return {'results': [], 'total': 0, 'page': page, 'per_page': per_page}

        try:
            must_clauses = []

            if query:
                must_clauses.append({
                    'multi_match': {
                        'query': query,
                        'fields': ['title^3', 'description^2', 'category', 'assigned_to'],
                        'type': 'best_fields',
                        'fuzziness': 'AUTO'
                    }
                })

            filter_clauses = []
            if filters:
                if filters.get('category'):
                    filter_clauses.append({'term': {'category': filters['category']}})
                if filters.get('priority'):
                    filter_clauses.append({'term': {'priority': filters['priority']}})
                if filters.get('status'):
                    filter_clauses.append({'term': {'status': filters['status']}})
                if filters.get('assigned_to'):
                    filter_clauses.append({'term': {'assigned_to': filters['assigned_to']}})

            body = {
                'query': {
                    'bool': {
                        'must': must_clauses if must_clauses else [{'match_all': {}}],
                        'filter': filter_clauses
                    }
                },
                'from': (page - 1) * per_page,
                'size': per_page,
                'sort': [{'_score': 'desc'}, {'created_at': 'desc'}]
            }

            response = self.es.search(index='tickets', body=body)

            results = [hit['_source'] for hit in response['hits']['hits']]
            total = response['hits']['total']['value']

            return {
                'results': results,
                'total': total,
                'page': page,
                'per_page': per_page,
                'pages': (total + per_page - 1) // per_page
            }
        except Exception as e:
            logger.error(f"Error searching tickets: {e}")
            return {'results': [], 'total': 0, 'page': page, 'per_page': per_page}

    def delete_item(self, item_id):
        """Delete an item from the index"""
        if not self.es:
            return False

        try:
            self.es.delete(index='items', id=item_id)
            return True
        except Exception as e:
            logger.error(f"Error deleting item {item_id}: {e}")
            return False

    def delete_ticket(self, ticket_id):
        """Delete a ticket from the index"""
        if not self.es:
            return False

        try:
            self.es.delete(index='tickets', id=ticket_id)
            return True
        except Exception as e:
            logger.error(f"Error deleting ticket {ticket_id}: {e}")
            return False

    def reindex_all(self, db):
        """Reindex all entities - useful for initial setup or data migration"""
        if not self.es:
            logger.error("Elasticsearch not connected")
            return False

        try:
            from app import Item, Ticket, AuditLog

            # Reindex all items
            items = Item.query.all()
            self.bulk_index_items(items)
            logger.info(f"Reindexed {len(items)} items")

            # Reindex all tickets
            tickets = Ticket.query.all()
            for ticket in tickets:
                self.index_ticket(ticket)
            logger.info(f"Reindexed {len(tickets)} tickets")

            return True
        except Exception as e:
            logger.error(f"Error reindexing all: {e}")
            return False


# Global instance
es_service = ElasticsearchService()
