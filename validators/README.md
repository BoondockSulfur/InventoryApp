# Validators - Pydantic Input Validation

This directory contains Pydantic validation schemas for API input validation, providing strong typing, automatic validation, and clear error messages.

## Why Pydantic?

**Benefits:**
- 🔒 **Security**: Prevents invalid/malicious data from entering the database
- ✅ **Type Safety**: Automatic type checking and conversion
- 📝 **Clear Errors**: Detailed validation error messages for API consumers
- 🚀 **Performance**: Fast validation using type hints
- 📚 **Self-Documenting**: Schemas serve as API documentation

## Installation

Pydantic should be added to `requirements.txt`:

```
pydantic==2.5.0
```

Then install:

```bash
pip install pydantic
```

## Usage Examples

### Example 1: Manual Validation

```python
from validators.ticket_validators import CategoryCreateSchema
from pydantic import ValidationError

@app.route('/api/category', methods=['POST'])
@login_required
def create_category():
    try:
        # Validate incoming JSON
        data = CategoryCreateSchema(**request.get_json())
    except ValidationError as e:
        return jsonify({
            'success': False,
            'errors': e.errors()
        }), 400

    # Use validated data
    category = TicketCategory(**data.dict())
    db.session.add(category)
    db.session.commit()

    return jsonify({'success': True, 'id': category.id})
```

### Example 2: Using Decorator (Recommended)

```python
from validators.ticket_validators import CategoryCreateSchema, validate_request_json

@app.route('/api/category', methods=['POST'])
@login_required
@validate_request_json(CategoryCreateSchema)
def create_category(validated_data):
    # validated_data is already validated and typed
    category = TicketCategory(**validated_data.dict())
    db.session.add(category)
    db.session.commit()

    return jsonify({'success': True, 'id': category.id})
```

### Example 3: Update with Partial Data

```python
from validators.ticket_validators import CategoryUpdateSchema

@app.route('/api/category/<int:id>', methods=['PUT'])
@login_required
@validate_request_json(CategoryUpdateSchema)
def update_category(validated_data, id):
    category = db.session.get(TicketCategory, id)
    if not category:
        return jsonify({'error': 'Not found'}), 404

    # Update only provided fields (exclude_unset=True)
    for key, value in validated_data.dict(exclude_unset=True).items():
        setattr(category, key, value)

    db.session.commit()
    return jsonify({'success': True})
```

## Available Schemas

### Ticket System (`ticket_validators.py`)

| Schema | Purpose | Validates |
|--------|---------|-----------|
| `CategoryCreateSchema` | Create category | name, description, color, icon, sla_hours |
| `CategoryUpdateSchema` | Update category | Optional fields from create schema |
| `PriorityCreateSchema` | Create priority | name, level (1-5), color, icon |
| `PriorityUpdateSchema` | Update priority | Optional fields from create schema |
| `StatusCreateSchema` | Create status | name, color, icon, is_closed |
| `StatusUpdateSchema` | Update status | Optional fields from create schema |
| `CustomFieldCreateSchema` | Create custom field | name, field_type, required, options |
| `TemplateCreateSchema` | Create template | name, title_template, description_template |
| `SLARuleCreateSchema` | Create SLA rule | name, response_time, resolution_time |

## Validation Features

### 1. **String Length Validation**
```python
name: str = Field(..., min_length=1, max_length=100)
```

### 2. **Regex Validation**
```python
color: str = Field(..., regex=r'^#[0-9A-Fa-f]{6}$')
```

### 3. **Numeric Range Validation**
```python
sla_hours: int = Field(..., ge=1, le=720)  # 1-720 hours
```

### 4. **Custom Validators**
```python
@validator('icon')
def validate_icon(cls, v):
    allowed_icons = ['tag', 'bug', 'gear']
    if v not in allowed_icons:
        raise ValueError(f'Icon must be one of: {allowed_icons}')
    return v
```

### 5. **Cross-Field Validation**
```python
@validator('resolution_time_hours')
def validate_resolution_time(cls, v, values):
    response_time = values.get('response_time_hours')
    if v < response_time:
        raise ValueError('Resolution time must be >= response time')
    return v
```

## Error Response Format

When validation fails, the API returns:

```json
{
  "success": false,
  "message": "Validation error",
  "errors": [
    {
      "loc": ["color"],
      "msg": "string does not match regex \"^#[0-9A-Fa-f]{6}$\"",
      "type": "value_error.str.regex"
    },
    {
      "loc": ["sla_hours"],
      "msg": "ensure this value is greater than or equal to 1",
      "type": "value_error.number.not_ge"
    }
  ]
}
```

## Adding New Validators

To add validation for a new API endpoint:

1. **Create a new schema class:**

```python
class MyEntityCreateSchema(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., regex=r'^[^@]+@[^@]+\.[^@]+$')

    @validator('name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Name cannot be empty')
        return v.strip()

    class Config:
        extra = 'ignore'  # Ignore unknown fields
```

2. **Use in route:**

```python
@app.route('/api/my-entity', methods=['POST'])
@validate_request_json(MyEntityCreateSchema)
def create_my_entity(validated_data):
    # Your logic here
    pass
```

## Best Practices

1. ✅ **Always validate user input** - Never trust client data
2. ✅ **Use descriptive field names** - Makes errors clear
3. ✅ **Set reasonable limits** - Prevent DoS attacks via large inputs
4. ✅ **Whitelist allowed values** - Use enums/validators for restricted fields
5. ✅ **Trim whitespace** - Use validators to clean input
6. ✅ **Use `exclude_unset=True`** for updates - Only update provided fields
7. ✅ **Set `extra = 'ignore'`** - Gracefully handle extra fields from clients

## Security Benefits

- ❌ **Prevents SQL Injection** - Type checking ensures correct data types
- ❌ **Prevents XSS** - Length limits and character whitelists
- ❌ **Prevents DoS** - Maximum length limits on all fields
- ❌ **Prevents Invalid Data** - Custom validators ensure business rules
- ✅ **Audit Trail** - Validation errors are logged

## Testing Validators

```python
import pytest
from validators.ticket_validators import CategoryCreateSchema
from pydantic import ValidationError

def test_category_valid():
    data = {
        'name': 'Bug Report',
        'color': '#FF5733',
        'icon': 'bug',
        'sla_hours': 24
    }
    schema = CategoryCreateSchema(**data)
    assert schema.name == 'Bug Report'

def test_category_invalid_color():
    with pytest.raises(ValidationError):
        CategoryCreateSchema(
            name='Test',
            color='red',  # Invalid hex color
        )
```

## Migration Guide

To migrate existing unvalidated endpoints:

1. Create Pydantic schema for the endpoint
2. Add `@validate_request_json(YourSchema)` decorator
3. Update route signature to accept `validated_data` parameter
4. Replace `request.get_json()` with `validated_data.dict()`
5. Test with valid and invalid inputs
6. Update API documentation

## References

- [Pydantic Documentation](https://docs.pydantic.dev/)
- [Flask + Pydantic Guide](https://flask-pydantic.readthedocs.io/)
- [OWASP Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
