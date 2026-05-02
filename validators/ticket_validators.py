# -*- coding: utf-8 -*-
"""
Pydantic Validators for Ticket System API
==========================================

This module demonstrates how to use Pydantic for input validation
in API endpoints, providing strong typing and automatic validation.

Example Usage:
--------------
from validators.ticket_validators import CategoryCreateSchema

@app.route('/api/category', methods=['POST'])
def create_category():
    try:
        data = CategoryCreateSchema(**request.get_json())
    except ValidationError as e:
        return jsonify({'success': False, 'errors': e.errors()}), 400

    # Use validated data
    category = TicketCategory(**data.dict())
    db.session.add(category)
    db.session.commit()
    return jsonify({'success': True, 'id': category.id})
"""

from pydantic import BaseModel, Field, validator, ValidationError
from typing import Optional, List
import re


# ============================================================================
# TICKET CATEGORY SCHEMAS
# ============================================================================

class CategoryCreateSchema(BaseModel):
    """Validation schema for creating a ticket category"""

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Category name"
    )
    description: Optional[str] = Field(
        None,
        max_length=500,
        description="Category description"
    )
    color: str = Field(
        default='#6c757d',
        regex=r'^#[0-9A-Fa-f]{6}$',
        description="Hex color code (e.g., #FF5733)"
    )
    icon: str = Field(
        default='tag',
        max_length=50,
        description="Bootstrap icon name"
    )
    sla_hours: int = Field(
        default=24,
        ge=1,
        le=720,  # Max 30 days
        description="SLA hours for this category"
    )

    @validator('name')
    def validate_name(cls, v):
        """Ensure name doesn't contain only whitespace"""
        if not v.strip():
            raise ValueError('Name cannot be empty or whitespace only')
        return v.strip()

    @validator('icon')
    def validate_icon(cls, v):
        """Whitelist of allowed Bootstrap Icons"""
        allowed_icons = [
            'tag', 'bug', 'gear', 'folder', 'star', 'heart',
            'bell', 'calendar', 'chat', 'clipboard', 'cloud',
            'code', 'database', 'envelope', 'file', 'flag',
            'gift', 'graph', 'hash', 'home', 'info-circle',
            'key', 'lightning', 'list', 'lock', 'map',
            'megaphone', 'money', 'network', 'palette', 'pencil',
            'person', 'phone', 'question-circle', 'rocket', 'search',
            'server', 'shield', 'sliders', 'speedometer', 'terminal',
            'tools', 'trash', 'trophy', 'truck', 'upload',
            'wallet', 'wifi', 'wrench', 'x-circle', 'zoom-in'
        ]

        if v not in allowed_icons:
            raise ValueError(
                f'Icon must be one of the allowed icons. '
                f'Received: {v}. See Bootstrap Icons documentation.'
            )
        return v

    @validator('color')
    def validate_color_brightness(cls, v):
        """Ensure color is not too light (for readability)"""
        # Remove '#' and convert to RGB
        hex_color = v.lstrip('#')
        r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)

        # Calculate brightness (0-255)
        brightness = (r * 299 + g * 587 + b * 114) / 1000

        if brightness > 220:
            raise ValueError(
                f'Color too light for readability (brightness: {brightness:.0f}/255). '
                f'Please use a darker color.'
            )
        return v

    class Config:
        # Allow extra fields to be ignored (graceful degradation)
        extra = 'ignore'


class CategoryUpdateSchema(BaseModel):
    """Validation schema for updating a ticket category"""

    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    color: Optional[str] = Field(None, regex=r'^#[0-9A-Fa-f]{6}$')
    icon: Optional[str] = Field(None, max_length=50)
    sla_hours: Optional[int] = Field(None, ge=1, le=720)

    # Reuse validators from CreateSchema
    _validate_name = validator('name', allow_reuse=True)(CategoryCreateSchema.validate_name)
    _validate_icon = validator('icon', allow_reuse=True)(CategoryCreateSchema.validate_icon)
    _validate_color = validator('color', allow_reuse=True)(CategoryCreateSchema.validate_color_brightness)

    class Config:
        extra = 'ignore'


# ============================================================================
# TICKET PRIORITY SCHEMAS
# ============================================================================

class PriorityCreateSchema(BaseModel):
    """Validation schema for creating a ticket priority"""

    name: str = Field(..., min_length=1, max_length=50)
    level: int = Field(..., ge=1, le=5, description="Priority level (1=Lowest, 5=Critical)")
    color: str = Field(default='#6c757d', regex=r'^#[0-9A-Fa-f]{6}$')
    icon: str = Field(default='flag', max_length=50)

    @validator('name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Name cannot be empty')
        return v.strip()

    @validator('icon')
    def validate_icon(cls, v):
        allowed_icons = ['flag', 'exclamation-triangle', 'alert', 'bell', 'star']
        if v not in allowed_icons:
            raise ValueError(f'Icon must be one of: {", ".join(allowed_icons)}')
        return v

    class Config:
        extra = 'ignore'


class PriorityUpdateSchema(BaseModel):
    """Validation schema for updating a ticket priority"""

    name: Optional[str] = Field(None, min_length=1, max_length=50)
    level: Optional[int] = Field(None, ge=1, le=5)
    color: Optional[str] = Field(None, regex=r'^#[0-9A-Fa-f]{6}$')
    icon: Optional[str] = Field(None, max_length=50)

    _validate_name = validator('name', allow_reuse=True)(PriorityCreateSchema.validate_name)
    _validate_icon = validator('icon', allow_reuse=True)(PriorityCreateSchema.validate_icon)

    class Config:
        extra = 'ignore'


# ============================================================================
# TICKET STATUS SCHEMAS
# ============================================================================

class StatusCreateSchema(BaseModel):
    """Validation schema for creating a ticket status"""

    name: str = Field(..., min_length=1, max_length=50)
    color: str = Field(default='#6c757d', regex=r'^#[0-9A-Fa-f]{6}$')
    icon: str = Field(default='circle', max_length=50)
    is_closed: bool = Field(default=False, description="Whether this status represents a closed ticket")

    @validator('name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Name cannot be empty')
        return v.strip()

    class Config:
        extra = 'ignore'


class StatusUpdateSchema(BaseModel):
    """Validation schema for updating a ticket status"""

    name: Optional[str] = Field(None, min_length=1, max_length=50)
    color: Optional[str] = Field(None, regex=r'^#[0-9A-Fa-f]{6}$')
    icon: Optional[str] = Field(None, max_length=50)
    is_closed: Optional[bool] = None

    _validate_name = validator('name', allow_reuse=True)(StatusCreateSchema.validate_name)

    class Config:
        extra = 'ignore'


# ============================================================================
# TICKET CUSTOM FIELD SCHEMAS
# ============================================================================

class CustomFieldCreateSchema(BaseModel):
    """Validation schema for creating a custom field"""

    name: str = Field(..., min_length=1, max_length=100)
    field_type: str = Field(..., regex=r'^(text|number|date|select|checkbox|textarea)$')
    required: bool = Field(default=False)
    options: Optional[List[str]] = Field(None, description="Options for 'select' field type")

    @validator('name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Name cannot be empty')
        # Ensure name is valid for form fields (no special characters)
        if not re.match(r'^[a-zA-Z0-9_\s-]+$', v):
            raise ValueError('Name can only contain letters, numbers, spaces, hyphens, and underscores')
        return v.strip()

    @validator('options')
    def validate_options(cls, v, values):
        """Ensure options are provided for 'select' type"""
        if values.get('field_type') == 'select':
            if not v or len(v) == 0:
                raise ValueError('Options are required for select field type')
            if len(v) > 50:
                raise ValueError('Maximum 50 options allowed')
        return v

    class Config:
        extra = 'ignore'


# ============================================================================
# TICKET TEMPLATE SCHEMAS
# ============================================================================

class TemplateCreateSchema(BaseModel):
    """Validation schema for creating a ticket template"""

    name: str = Field(..., min_length=1, max_length=100)
    title_template: str = Field(..., min_length=1, max_length=200)
    description_template: str = Field(..., max_length=5000)
    category_id: Optional[int] = Field(None, ge=1)
    priority_id: Optional[int] = Field(None, ge=1)

    @validator('name', 'title_template')
    def validate_not_empty(cls, v):
        if not v.strip():
            raise ValueError('Field cannot be empty')
        return v.strip()

    class Config:
        extra = 'ignore'


# ============================================================================
# SLA RULE SCHEMAS
# ============================================================================

class SLARuleCreateSchema(BaseModel):
    """Validation schema for creating an SLA rule"""

    name: str = Field(..., min_length=1, max_length=100)
    category_id: Optional[int] = Field(None, ge=1)
    priority_id: Optional[int] = Field(None, ge=1)
    response_time_hours: int = Field(..., ge=1, le=168, description="Response time in hours (max 1 week)")
    resolution_time_hours: int = Field(..., ge=1, le=720, description="Resolution time in hours (max 30 days)")

    @validator('name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Name cannot be empty')
        return v.strip()

    @validator('resolution_time_hours')
    def validate_resolution_time(cls, v, values):
        """Ensure resolution time is greater than response time"""
        response_time = values.get('response_time_hours')
        if response_time and v < response_time:
            raise ValueError('Resolution time must be greater than or equal to response time')
        return v

    class Config:
        extra = 'ignore'


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def validate_request_json(schema_class):
    """
    Decorator to validate request JSON against a Pydantic schema

    Usage:
        @app.route('/api/category', methods=['POST'])
        @validate_request_json(CategoryCreateSchema)
        def create_category(validated_data):
            category = TicketCategory(**validated_data.dict())
            # ...
    """
    def decorator(func):
        from functools import wraps
        from flask import request, jsonify

        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Validate request JSON
                validated_data = schema_class(**request.get_json())
                # Pass validated data to the route function
                return func(validated_data, *args, **kwargs)
            except ValidationError as e:
                # Return validation errors
                return jsonify({
                    'success': False,
                    'message': 'Validation error',
                    'errors': e.errors()
                }), 400
            except Exception as e:
                return jsonify({
                    'success': False,
                    'message': f'Invalid JSON: {str(e)}'
                }), 400

        return wrapper
    return decorator


# ============================================================================
# EXAMPLE USAGE IN ROUTES
# ============================================================================

"""
EXAMPLE 1: Manual validation in route
--------------------------------------

from validators.ticket_validators import CategoryCreateSchema
from pydantic import ValidationError

@app.route('/api/category', methods=['POST'])
@login_required
@requires_permission('manage_settings')
def create_category():
    try:
        # Validate incoming data
        data = CategoryCreateSchema(**request.get_json())
    except ValidationError as e:
        return jsonify({
            'success': False,
            'message': 'Validation failed',
            'errors': e.errors()
        }), 400

    # Use validated data (guaranteed to be correct)
    category = TicketCategory(
        name=data.name,
        description=data.description,
        color=data.color,
        icon=data.icon,
        sla_hours=data.sla_hours
    )
    db.session.add(category)
    db.session.commit()

    return jsonify({
        'success': True,
        'id': category.id,
        'message': 'Category created successfully'
    })


EXAMPLE 2: Using decorator for cleaner code
--------------------------------------------

@app.route('/api/category', methods=['POST'])
@login_required
@requires_permission('manage_settings')
@validate_request_json(CategoryCreateSchema)
def create_category(validated_data):
    # validated_data is already a CategoryCreateSchema instance
    category = TicketCategory(**validated_data.dict())
    db.session.add(category)
    db.session.commit()

    return jsonify({'success': True, 'id': category.id})


EXAMPLE 3: Update operation
----------------------------

@app.route('/api/category/<int:id>', methods=['PUT'])
@login_required
@requires_permission('manage_settings')
@validate_request_json(CategoryUpdateSchema)
def update_category(validated_data, id):
    category = db.session.get(TicketCategory, id)
    if not category:
        return jsonify({'success': False, 'error': 'Not found'}), 404

    # Update only provided fields
    update_data = validated_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(category, key, value)

    db.session.commit()
    return jsonify({'success': True})
"""
