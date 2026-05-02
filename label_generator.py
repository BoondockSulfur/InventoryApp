# -*- coding: utf-8 -*-
"""
Professional Label Generator for InventoryApp
Supports barcodes, QR codes, and custom label templates
"""

from PIL import Image, ImageDraw, ImageFont
import qrcode
import io
import base64
from datetime import datetime

# Try to import barcode generation library
try:
    import barcode
    from barcode.writer import ImageWriter
    BARCODE_AVAILABLE = True
except ImportError:
    BARCODE_AVAILABLE = False
    print("⚠️  python-barcode not available. Install with: pip install python-barcode")


# Label size presets (in millimeters, converted to pixels at 300 DPI)
LABEL_SIZES = {
    'small': {
        'name': '62mm x 29mm (Small Address Label)',
        'width_mm': 62,
        'height_mm': 29,
        'width_px': 730,   # 62mm at 300 DPI
        'height_px': 341   # 29mm at 300 DPI
    },
    'medium': {
        'name': '62mm x 100mm (Shipping Label)',
        'width_mm': 62,
        'height_mm': 100,
        'width_px': 730,
        'height_px': 1181
    },
    'large': {
        'name': '102mm x 152mm (4" x 6" Shipping Label)',
        'width_mm': 102,
        'height_mm': 152,
        'width_px': 1204,
        'height_px': 1795
    },
    'square': {
        'name': '50mm x 50mm (Square QR Label)',
        'width_mm': 50,
        'height_mm': 50,
        'width_px': 591,
        'height_px': 591
    },
    'custom': {
        'name': 'Custom Size',
        'width_mm': 80,
        'height_mm': 40,
        'width_px': 945,
        'height_px': 472
    }
}


class LabelGenerator:
    """Professional label generator with barcode and QR code support"""

    def __init__(self, label_size='medium', dpi=300):
        """
        Initialize label generator

        Args:
            label_size: One of 'small', 'medium', 'large', 'square', 'custom'
            dpi: Dots per inch for label resolution (default: 300)
        """
        self.dpi = dpi
        self.label_size = LABEL_SIZES.get(label_size, LABEL_SIZES['medium'])
        self.width = self.label_size['width_px']
        self.height = self.label_size['height_px']

    def create_item_label(self, item_data, include_qr=True, include_barcode=True):
        """
        Create a comprehensive item label

        Args:
            item_data: Dictionary with item information
                - name: Item name
                - id: Item ID
                - serial: Serial number (optional)
                - category: Category (optional)
                - location: Location (optional)
                - barcode_value: Value for barcode (defaults to ID)
                - company: Company name (optional)
            include_qr: Include QR code
            include_barcode: Include barcode

        Returns:
            PIL Image object
        """
        # Create white background
        label = Image.new('RGB', (self.width, self.height), 'white')
        draw = ImageDraw.Draw(label)

        # Calculate margins (5% of dimensions)
        margin_x = int(self.width * 0.05)
        margin_y = int(self.height * 0.05)

        # Current Y position
        current_y = margin_y

        # Try to use a nice font, fall back to default if not available
        try:
            title_font = ImageFont.truetype("arial.ttf", size=int(self.height * 0.08))
            detail_font = ImageFont.truetype("arial.ttf", size=int(self.height * 0.05))
            small_font = ImageFont.truetype("arial.ttf", size=int(self.height * 0.04))
        except:
            title_font = ImageFont.load_default()
            detail_font = ImageFont.load_default()
            small_font = ImageFont.load_default()

        # Draw title (item name)
        item_name = str(item_data.get('name', 'Unknown Item'))
        self._draw_text_wrapped(
            draw, item_name, margin_x, current_y,
            self.width - 2 * margin_x, title_font, 'black'
        )
        current_y += int(self.height * 0.12)

        # Draw separator line
        draw.line(
            [(margin_x, current_y), (self.width - margin_x, current_y)],
            fill='black', width=2
        )
        current_y += int(self.height * 0.03)

        # Reserve space for codes if needed
        code_width = 0
        if include_qr or include_barcode:
            code_width = int(self.width * 0.35)

        # Draw details (left side)
        details_width = self.width - 2 * margin_x - code_width - margin_x

        # Item ID
        if 'id' in item_data:
            text = f"ID: {item_data['id']}"
            draw.text((margin_x, current_y), text, fill='black', font=detail_font)
            current_y += int(self.height * 0.07)

        # Serial Number
        if item_data.get('serial'):
            text = f"S/N: {item_data['serial']}"
            draw.text((margin_x, current_y), text, fill='black', font=detail_font)
            current_y += int(self.height * 0.07)

        # Category
        if item_data.get('category'):
            text = f"Cat: {item_data['category']}"
            self._draw_text_wrapped(
                draw, text, margin_x, current_y,
                details_width, small_font, 'gray'
            )
            current_y += int(self.height * 0.06)

        # Location
        if item_data.get('location'):
            text = f"Loc: {item_data['location']}"
            self._draw_text_wrapped(
                draw, text, margin_x, current_y,
                details_width, small_font, 'gray'
            )
            current_y += int(self.height * 0.06)

        # QR Code (right side)
        code_x = self.width - margin_x - code_width
        code_y = int(self.height * 0.15)

        if include_qr:
            qr_data = self._generate_item_qr_data(item_data)
            qr_image = self._create_qr_code(qr_data, size=code_width)
            if qr_image:
                label.paste(qr_image, (code_x, code_y))
                code_y += code_width + int(self.height * 0.03)

        # Barcode (below QR or on right side)
        if include_barcode and BARCODE_AVAILABLE:
            barcode_value = str(item_data.get('barcode_value', item_data.get('id', '000000')))
            barcode_image = self._create_barcode(barcode_value, width=code_width)
            if barcode_image:
                barcode_height = barcode_image.size[1]
                if code_y + barcode_height < self.height - margin_y:
                    label.paste(barcode_image, (code_x, code_y))

        # Footer (company name and date)
        footer_y = self.height - margin_y - int(self.height * 0.05)
        company = item_data.get('company', 'InventoryApp')
        date_str = datetime.now().strftime('%Y-%m-%d')
        footer_text = f"{company} | {date_str}"
        draw.text((margin_x, footer_y), footer_text, fill='gray', font=small_font)

        return label

    def create_simple_qr_label(self, data, title=None):
        """
        Create a simple QR code label

        Args:
            data: Data to encode in QR code (string or dict)
            title: Optional title text

        Returns:
            PIL Image object
        """
        label = Image.new('RGB', (self.width, self.height), 'white')
        draw = ImageDraw.Draw(label)

        margin = int(self.width * 0.05)

        # Draw title if provided
        current_y = margin
        if title:
            try:
                font = ImageFont.truetype("arial.ttf", size=int(self.height * 0.08))
            except:
                font = ImageFont.load_default()

            draw.text((margin, current_y), str(title), fill='black', font=font)
            current_y += int(self.height * 0.12)

        # Generate QR code (centered)
        qr_size = min(self.width, self.height) - 2 * margin
        if title:
            qr_size = int((self.height - current_y - margin) * 0.9)

        if isinstance(data, dict):
            qr_data = '\n'.join([f"{k}: {v}" for k, v in data.items()])
        else:
            qr_data = str(data)

        qr_image = self._create_qr_code(qr_data, size=qr_size)
        if qr_image:
            qr_x = (self.width - qr_size) // 2
            qr_y = current_y + (self.height - current_y - margin - qr_size) // 2
            label.paste(qr_image, (qr_x, qr_y))

        return label

    def create_barcode_label(self, value, title=None, barcode_type='code128'):
        """
        Create a barcode label

        Args:
            value: Value to encode in barcode
            title: Optional title text
            barcode_type: Type of barcode (code128, code39, ean13, etc.)

        Returns:
            PIL Image object
        """
        if not BARCODE_AVAILABLE:
            return self._create_error_label("Barcode library not available")

        label = Image.new('RGB', (self.width, self.height), 'white')
        draw = ImageDraw.Draw(label)

        margin = int(self.width * 0.05)
        current_y = margin

        # Draw title if provided
        if title:
            try:
                font = ImageFont.truetype("arial.ttf", size=int(self.height * 0.08))
            except:
                font = ImageFont.load_default()

            draw.text((margin, current_y), str(title), fill='black', font=font)
            current_y += int(self.height * 0.12)

        # Generate barcode
        barcode_width = self.width - 2 * margin
        barcode_image = self._create_barcode(str(value), width=barcode_width, barcode_type=barcode_type)

        if barcode_image:
            # Center barcode vertically
            barcode_height = barcode_image.size[1]
            barcode_y = current_y + (self.height - current_y - margin - barcode_height) // 2
            label.paste(barcode_image, (margin, barcode_y))

        return label

    def _create_qr_code(self, data, size=300):
        """Generate QR code image"""
        try:
            qr = qrcode.QRCode(
                version=None,  # Auto-size
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=10,
                border=2,
            )
            qr.add_data(data)
            qr.make(fit=True)

            qr_image = qr.make_image(fill_color="black", back_color="white")
            qr_image = qr_image.resize((size, size), Image.Resampling.LANCZOS)

            return qr_image
        except Exception as e:
            print(f"Error creating QR code: {e}")
            return None

    def _create_barcode(self, value, width=400, barcode_type='code128'):
        """Generate barcode image"""
        if not BARCODE_AVAILABLE:
            return None

        try:
            # Get barcode class
            barcode_class = barcode.get_barcode_class(barcode_type)

            # Create barcode
            writer = ImageWriter()
            barcode_instance = barcode_class(value, writer=writer)

            # Generate image
            buffer = io.BytesIO()
            barcode_instance.write(buffer, options={
                'module_width': max(0.2, width / 500),  # Scale module width
                'module_height': 15.0,
                'quiet_zone': 2.0,
                'text_distance': 3.0,
                'font_size': 10
            })

            buffer.seek(0)
            barcode_image = Image.open(buffer)

            # Resize to fit width
            aspect_ratio = barcode_image.size[1] / barcode_image.size[0]
            new_height = int(width * aspect_ratio)
            barcode_image = barcode_image.resize((width, new_height), Image.Resampling.LANCZOS)

            return barcode_image
        except Exception as e:
            print(f"Error creating barcode: {e}")
            return None

    def _draw_text_wrapped(self, draw, text, x, y, max_width, font, fill='black'):
        """Draw text with word wrapping"""
        words = text.split()
        lines = []
        current_line = []

        for word in words:
            test_line = ' '.join(current_line + [word])
            bbox = draw.textbbox((0, 0), test_line, font=font)
            width = bbox[2] - bbox[0]

            if width <= max_width:
                current_line.append(word)
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]

        if current_line:
            lines.append(' '.join(current_line))

        # Draw lines
        for i, line in enumerate(lines):
            line_y = y + i * int(self.height * 0.05)
            draw.text((x, line_y), line, fill=fill, font=font)

    def _generate_item_qr_data(self, item_data):
        """Generate QR code data string from item data"""
        parts = []

        if 'id' in item_data:
            parts.append(f"ID:{item_data['id']}")
        if 'name' in item_data:
            parts.append(f"Name:{item_data['name']}")
        if 'serial' in item_data:
            parts.append(f"Serial:{item_data['serial']}")
        if 'category' in item_data:
            parts.append(f"Category:{item_data['category']}")
        if 'location' in item_data:
            parts.append(f"Location:{item_data['location']}")

        return '\n'.join(parts) if parts else str(item_data.get('id', 'Unknown'))

    def _create_error_label(self, message):
        """Create an error label"""
        label = Image.new('RGB', (self.width, self.height), 'white')
        draw = ImageDraw.Draw(label)

        try:
            font = ImageFont.truetype("arial.ttf", size=20)
        except:
            font = ImageFont.load_default()

        margin = int(self.width * 0.05)
        draw.text((margin, margin), f"Error: {message}", fill='red', font=font)

        return label

    def image_to_base64(self, image):
        """Convert PIL Image to base64 string for web display"""
        buffer = io.BytesIO()
        image.save(buffer, format='PNG')
        buffer.seek(0)
        return base64.b64encode(buffer.read()).decode()


def init_label_routes(app, db, require_permission):
    """Initialize label generator routes"""
    from flask import Blueprint, render_template, request, jsonify, send_file
    from flask_login import login_required
    from functools import wraps
    import tempfile
    import os

    label_bp = Blueprint('labels', __name__, url_prefix='/labels')

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

    @label_bp.route('/generator')
    @login_required
    def generator():
        """Label generator page"""
        return render_template('labels/generator.html',
                             label_sizes=LABEL_SIZES,
                             barcode_available=BARCODE_AVAILABLE)

    @label_bp.route('/api/generate', methods=['POST'])
    @login_required
    def api_generate():
        """API: Generate label"""
        data = request.get_json()

        label_type = data.get('type', 'item')  # item, qr, barcode
        label_size = data.get('size', 'medium')

        generator = LabelGenerator(label_size=label_size)

        try:
            if label_type == 'item':
                item_data = data.get('item_data', {})
                include_qr = data.get('include_qr', True)
                include_barcode = data.get('include_barcode', True)

                label_image = generator.create_item_label(
                    item_data,
                    include_qr=include_qr,
                    include_barcode=include_barcode
                )

            elif label_type == 'qr':
                qr_data = data.get('qr_data', '')
                title = data.get('title')
                label_image = generator.create_simple_qr_label(qr_data, title=title)

            elif label_type == 'barcode':
                barcode_value = data.get('barcode_value', '')
                title = data.get('title')
                barcode_type = data.get('barcode_type', 'code128')
                label_image = generator.create_barcode_label(
                    barcode_value,
                    title=title,
                    barcode_type=barcode_type
                )
            else:
                return jsonify({'success': False, 'error': 'Invalid label type'}), 400

            # Convert to base64
            image_base64 = generator.image_to_base64(label_image)

            return jsonify({
                'success': True,
                'image': f'data:image/png;base64,{image_base64}',
                'width': generator.width,
                'height': generator.height
            })

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @label_bp.route('/api/generate-item/<int:item_id>')
    @login_required
    def api_generate_item(item_id):
        """API: Generate label for specific item"""
        from app import Item

        item = db.session.get(Item, item_id)
        if not item:
            return jsonify({'success': False, 'error': 'Item not found'}), 404

        # Build item data
        item_data = {
            'id': item.id,
            'name': item.name,
            'serial': item.serial_number if hasattr(item, 'serial_number') else None,
            'category': item.category.name if item.category else None,
            'location': item.location.name if item.location else None,
            'barcode_value': item.id
        }

        label_size = request.args.get('size', 'medium')
        include_qr = request.args.get('qr', '1') == '1'
        include_barcode = request.args.get('barcode', '1') == '1'

        generator = LabelGenerator(label_size=label_size)
        label_image = generator.create_item_label(
            item_data,
            include_qr=include_qr,
            include_barcode=include_barcode
        )

        # Save to temporary file and send
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
            label_image.save(tmp, format='PNG')
            tmp_path = tmp.name

        try:
            return send_file(
                tmp_path,
                mimetype='image/png',
                as_attachment=True,
                download_name=f'label_item_{item_id}.png'
            )
        finally:
            # Clean up temp file
            try:
                os.unlink(tmp_path)
            except:
                pass

    app.register_blueprint(label_bp)
