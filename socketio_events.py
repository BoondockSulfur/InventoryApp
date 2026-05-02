# -*- coding: utf-8 -*-
"""
WebSocket Events for InventoryApp
Provides real-time updates for inventory changes
"""

try:
    from flask_socketio import emit, join_room, leave_room, rooms
    from flask_login import current_user
    from flask import request
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False

if SOCKETIO_AVAILABLE:
    def register_socketio_events(socketio, app):
        """Register all SocketIO event handlers"""

        @socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            if current_user.is_authenticated:
                emit('connected', {
                    'message': 'Connected to InventoryApp real-time updates',
                    'user_id': current_user.id,
                    'username': current_user.username
                })
                app.logger.info(f'SocketIO: User {current_user.username} connected')
            else:
                emit('connected', {'message': 'Connected (anonymous)'})

        @socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            if current_user.is_authenticated:
                app.logger.info(f'SocketIO: User {current_user.username} disconnected')

        @socketio.on('join')
        def handle_join(data):
            """Join a specific room for targeted updates"""
            room = data.get('room')
            if room:
                join_room(room)
                emit('joined', {'room': room}, room=request.sid)
                app.logger.info(f'SocketIO: {current_user.username if current_user.is_authenticated else "Anonymous"} joined room {room}')

        @socketio.on('leave')
        def handle_leave(data):
            """Leave a room"""
            room = data.get('room')
            if room:
                leave_room(room)
                emit('left', {'room': room}, room=request.sid)

        # ─── Inventory Update Events ──────────────────────────────────

        def broadcast_item_created(item_data):
            """Broadcast when a new item is created"""
            socketio.emit('item_created', item_data, namespace='/')

        def broadcast_item_updated(item_data):
            """Broadcast when an item is updated"""
            socketio.emit('item_updated', item_data, namespace='/')

        def broadcast_item_deleted(item_id):
            """Broadcast when an item is deleted"""
            socketio.emit('item_deleted', {'id': item_id}, namespace='/')

        def broadcast_loan_created(loan_data):
            """Broadcast when a new loan is created"""
            socketio.emit('loan_created', loan_data, namespace='/')

        def broadcast_loan_returned(loan_data):
            """Broadcast when a loan is returned"""
            socketio.emit('loan_returned', loan_data, namespace='/')

        def broadcast_loan_overdue(loan_data):
            """Broadcast when a loan becomes overdue"""
            socketio.emit('loan_overdue', loan_data, namespace='/')

        def broadcast_user_activity(activity_data):
            """Broadcast user activity"""
            socketio.emit('user_activity', activity_data, namespace='/')

        # Store broadcast functions in app context for use in routes
        app.socketio_broadcast = {
            'item_created': broadcast_item_created,
            'item_updated': broadcast_item_updated,
            'item_deleted': broadcast_item_deleted,
            'loan_created': broadcast_loan_created,
            'loan_returned': broadcast_loan_returned,
            'loan_overdue': broadcast_loan_overdue,
            'user_activity': broadcast_user_activity,
        }

        return socketio

else:
    def register_socketio_events(socketio, app):
        """Dummy function when SocketIO is not available"""
        return socketio
