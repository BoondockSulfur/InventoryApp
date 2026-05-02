"""
API Gateway for InventoryApp Microservices

Handles:
- Request routing
- Authentication/Authorization
- Rate limiting
- Load balancing
- Request/Response transformation
"""

from flask import Flask, request, jsonify, Response
import requests
import jwt
import redis
from functools import wraps
from datetime import datetime, timedelta
import logging
from urllib.parse import urljoin

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# Redis for rate limiting and caching
redis_client = redis.Redis(host='redis', port=6379, decode_responses=True)

# Service Registry
SERVICES = {
    'auth': 'http://auth-service:8001',
    'items': 'http://item-service:8002',
    'budget': 'http://budget-service:8003',
    'labels': 'http://label-service:8004',
    'iot': 'http://iot-service:8005',
    'analytics': 'http://analytics-service:8006',
    'blockchain': 'http://blockchain-service:8007'
}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# Rate Limiting
# ============================================================================

def rate_limit(max_requests=100, window=60):
    """
    Rate limiting decorator

    Args:
        max_requests: Maximum requests allowed
        window: Time window in seconds
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get client IP
            client_ip = request.remote_addr

            # Create rate limit key
            key = f"rate_limit:{client_ip}:{f.__name__}"

            # Get current count
            current = redis_client.get(key)

            if current is None:
                # First request in window
                redis_client.setex(key, window, 1)
                return f(*args, **kwargs)
            elif int(current) < max_requests:
                # Increment counter
                redis_client.incr(key)
                return f(*args, **kwargs)
            else:
                # Rate limit exceeded
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': redis_client.ttl(key)
                }), 429

        return wrapped
    return decorator

# ============================================================================
# Authentication Middleware
# ============================================================================

def require_auth(f):
    """Require valid JWT token"""
    @wraps(f)
    def wrapped(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'error': 'No authorization token provided'}), 401

        try:
            # Remove "Bearer " prefix
            if token.startswith('Bearer '):
                token = token[7:]

            # Verify token
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = payload.get('user_id')
            request.tenant_id = payload.get('tenant_id')

            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

    return wrapped

# ============================================================================
# Service Proxy
# ============================================================================

def proxy_request(service_name, path):
    """
    Proxy request to microservice

    Args:
        service_name: Name of the service (auth, items, etc.)
        path: Path to forward to
    """
    if service_name not in SERVICES:
        return jsonify({'error': f'Unknown service: {service_name}'}), 404

    service_url = SERVICES[service_name]
    target_url = urljoin(service_url, path)

    # Forward headers (except Host)
    headers = {k: v for k, v in request.headers if k.lower() != 'host'}

    try:
        # Forward request
        if request.method == 'GET':
            response = requests.get(target_url, headers=headers, params=request.args, timeout=30)
        elif request.method == 'POST':
            response = requests.post(target_url, headers=headers, json=request.get_json(), timeout=30)
        elif request.method == 'PUT':
            response = requests.put(target_url, headers=headers, json=request.get_json(), timeout=30)
        elif request.method == 'DELETE':
            response = requests.delete(target_url, headers=headers, timeout=30)
        elif request.method == 'PATCH':
            response = requests.patch(target_url, headers=headers, json=request.get_json(), timeout=30)
        else:
            return jsonify({'error': 'Method not allowed'}), 405

        # Log request
        logger.info(f"{request.method} {target_url} - {response.status_code}")

        # Return response
        return Response(
            response.content,
            status=response.status_code,
            headers=dict(response.headers)
        )

    except requests.exceptions.Timeout:
        logger.error(f"Timeout calling {service_name}: {target_url}")
        return jsonify({'error': 'Service timeout'}), 504
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error calling {service_name}: {target_url}")
        return jsonify({'error': 'Service unavailable'}), 503
    except Exception as e:
        logger.error(f"Error calling {service_name}: {str(e)}")
        return jsonify({'error': 'Internal gateway error'}), 500

# ============================================================================
# Routes
# ============================================================================

@app.route('/health')
def health():
    """Gateway health check"""
    return jsonify({
        'status': 'healthy',
        'service': 'api-gateway',
        'timestamp': datetime.utcnow().isoformat(),
        'services': {name: 'unknown' for name in SERVICES.keys()}
    })

# Authentication routes (public)
@app.route('/api/auth/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@rate_limit(max_requests=10, window=60)  # Stricter rate limit for auth
def auth_proxy(path):
    """Proxy to authentication service"""
    return proxy_request('auth', f'/api/auth/{path}')

# Item routes (protected)
@app.route('/api/items/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@require_auth
@rate_limit(max_requests=100, window=60)
def items_proxy(path):
    """Proxy to item service"""
    return proxy_request('items', f'/api/items/{path}')

# Budget routes (protected)
@app.route('/api/budget/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@require_auth
@rate_limit(max_requests=100, window=60)
def budget_proxy(path):
    """Proxy to budget service"""
    return proxy_request('budget', f'/api/budget/{path}')

# Label routes (protected)
@app.route('/api/labels/<path:path>', methods=['GET', 'POST'])
@require_auth
@rate_limit(max_requests=50, window=60)
def labels_proxy(path):
    """Proxy to label service"""
    return proxy_request('labels', f'/api/labels/{path}')

# IoT routes (protected)
@app.route('/api/iot/<path:path>', methods=['GET', 'POST', 'PUT'])
@require_auth
@rate_limit(max_requests=1000, window=60)  # Higher limit for IoT devices
def iot_proxy(path):
    """Proxy to IoT service"""
    return proxy_request('iot', f'/api/iot/{path}')

# Analytics routes (protected)
@app.route('/api/analytics/<path:path>', methods=['GET', 'POST'])
@require_auth
@rate_limit(max_requests=50, window=60)
def analytics_proxy(path):
    """Proxy to analytics service"""
    return proxy_request('analytics', f'/api/analytics/{path}')

# Blockchain routes (protected)
@app.route('/api/blockchain/<path:path>', methods=['GET', 'POST'])
@require_auth
@rate_limit(max_requests=30, window=60)
def blockchain_proxy(path):
    """Proxy to blockchain service"""
    return proxy_request('blockchain', f'/api/blockchain/{path}')

# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# Main
# ============================================================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)
