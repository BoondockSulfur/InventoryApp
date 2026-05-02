# -*- coding: utf-8 -*-
"""
Printer Management System for InventoryApp
Supports both network printers and USB printers
"""

import platform
import subprocess
import json
import re
from datetime import datetime

# Regex to validate printer names (alphanumeric, spaces, hyphens, underscores, dots)
VALID_PRINTER_NAME = re.compile(r'^[\w\s.\-()]+$')


def _validate_printer_name(name):
    """Validate printer name to prevent injection attacks"""
    if not name or not VALID_PRINTER_NAME.match(name):
        raise ValueError(f"Invalid printer name: {name!r}")
    return name


class PrinterManager:
    """Unified printer management for network and USB printers"""

    def __init__(self):
        self.system = platform.system()

    def list_printers(self):
        """List all available printers (network and USB)"""
        printers = []

        if self.system == "Windows":
            printers = self._list_windows_printers()
        elif self.system == "Linux":
            printers = self._list_linux_printers()
        elif self.system == "Darwin":  # macOS
            printers = self._list_macos_printers()

        return printers

    def _list_windows_printers(self):
        """List printers on Windows using PowerShell"""
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-Printer | Select-Object Name,DriverName,PortName,PrinterStatus,Shared | ConvertTo-Json'],
                capture_output=True, text=True
            )

            if result.returncode == 0:
                printers_data = json.loads(result.stdout)

                # Handle single printer (not a list)
                if isinstance(printers_data, dict):
                    printers_data = [printers_data]

                printers = []
                for p in printers_data:
                    printer = {
                        'name': p.get('Name', ''),
                        'driver': p.get('DriverName', ''),
                        'port': p.get('PortName', ''),
                        'status': 'Ready' if p.get('PrinterStatus') == 0 else 'Error',
                        'shared': p.get('Shared', False),
                        'type': self._detect_printer_type(p.get('PortName', ''))
                    }
                    printers.append(printer)

                return printers
        except Exception as e:
            print(f"Error listing Windows printers: {e}")

        return []

    def _list_linux_printers(self):
        """List printers on Linux using lpstat"""
        try:
            result = subprocess.run(['lpstat', '-p', '-d'], capture_output=True, text=True)

            if result.returncode == 0:
                printers = []
                lines = result.stdout.split('\n')

                for line in lines:
                    if line.startswith('printer'):
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[1]
                            status = 'Ready' if 'idle' in line.lower() else 'Busy'

                            # Get printer details
                            details_result = subprocess.run(
                                ['lpstat', '-l', '-p', name],
                                capture_output=True, text=True
                            )

                            printer = {
                                'name': name,
                                'driver': '',
                                'port': '',
                                'status': status,
                                'shared': False,
                                'type': 'usb'  # Default to USB on Linux
                            }

                            if details_result.returncode == 0:
                                for detail_line in details_result.stdout.split('\n'):
                                    if 'Device URI' in detail_line:
                                        uri = detail_line.split(':')[-1].strip()
                                        printer['port'] = uri
                                        printer['type'] = self._detect_printer_type(uri)

                            printers.append(printer)

                return printers
        except Exception as e:
            print(f"Error listing Linux printers: {e}")

        return []

    def _list_macos_printers(self):
        """List printers on macOS using lpstat"""
        try:
            result = subprocess.run(['lpstat', '-p', '-v'], capture_output=True, text=True)

            if result.returncode == 0:
                printers = []
                lines = result.stdout.split('\n')

                current_printer = None
                for line in lines:
                    if line.startswith('printer'):
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[1]
                            status = 'Ready' if 'idle' in line.lower() else 'Busy'
                            current_printer = {
                                'name': name,
                                'driver': '',
                                'port': '',
                                'status': status,
                                'shared': False,
                                'type': 'usb'
                            }
                            printers.append(current_printer)
                    elif line.startswith('device for') and current_printer:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            uri = parts[1].strip()
                            current_printer['port'] = uri
                            current_printer['type'] = self._detect_printer_type(uri)

                return printers
        except Exception as e:
            print(f"Error listing macOS printers: {e}")

        return []

    def _detect_printer_type(self, port):
        """Detect printer type based on port/URI"""
        port_lower = str(port).lower()

        if 'usb' in port_lower:
            return 'usb'
        elif any(proto in port_lower for proto in ['ip', 'tcp', 'socket', 'lpd', 'ipp', 'http']):
            return 'network'
        elif 'file' in port_lower:
            return 'file'
        elif 'lpt' in port_lower or 'com' in port_lower:
            return 'parallel'
        else:
            return 'unknown'

    def get_default_printer(self):
        """Get the system default printer"""
        if self.system == "Windows":
            try:
                result = subprocess.run(
                    ['powershell', '-NoProfile', '-Command',
                     'Get-CimInstance Win32_Printer | Where-Object {$_.Default -eq $true} | Select-Object Name | ConvertTo-Json'],
                    capture_output=True, text=True
                )

                if result.returncode == 0 and result.stdout.strip():
                    data = json.loads(result.stdout)
                    return data.get('Name', '')
            except Exception as e:
                print(f"Error getting default Windows printer: {e}")

        elif self.system in ["Linux", "Darwin"]:
            try:
                result = subprocess.run(['lpstat', '-d'], capture_output=True, text=True)

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'system default destination' in line.lower():
                            parts = line.split(':')
                            if len(parts) >= 2:
                                return parts[1].strip()
            except Exception as e:
                print(f"Error getting default printer: {e}")

        return None

    def set_default_printer(self, printer_name):
        """Set the system default printer"""
        printer_name = _validate_printer_name(printer_name)

        if self.system == "Windows":
            try:
                result = subprocess.run(
                    ['powershell', '-NoProfile', '-Command',
                     '(New-Object -ComObject WScript.Network).SetDefaultPrinter($args[0])',
                     '-args', printer_name],
                    capture_output=True, text=True
                )
                return result.returncode == 0
            except Exception as e:
                print(f"Error setting default Windows printer: {e}")
                return False

        elif self.system in ["Linux", "Darwin"]:
            try:
                result = subprocess.run(['lpoptions', '-d', printer_name], capture_output=True)
                return result.returncode == 0
            except Exception as e:
                print(f"Error setting default printer: {e}")
                return False

        return False

    def test_print(self, printer_name, test_content="InventoryApp Test Print"):
        """Send a test print to the specified printer"""
        printer_name = _validate_printer_name(printer_name)

        if self.system == "Windows":
            return self._test_print_windows(printer_name, test_content)
        elif self.system in ["Linux", "Darwin"]:
            return self._test_print_unix(printer_name, test_content)

        return False

    def _test_print_windows(self, printer_name, test_content):
        """Test print on Windows"""
        try:
            import tempfile
            import os
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(f"{test_content}\n")
                f.write(f"Printer: {printer_name}\n")
                f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                temp_file = f.name

            try:
                result = subprocess.run(
                    ['powershell', '-NoProfile', '-Command',
                     'Get-Content $args[0] | Out-Printer -Name $args[1]',
                     '-args', temp_file, printer_name],
                    capture_output=True, text=True
                )
                return result.returncode == 0
            finally:
                try:
                    os.unlink(temp_file)
                except OSError:
                    pass
        except Exception as e:
            print(f"Error test printing on Windows: {e}")
            return False

    def _test_print_unix(self, printer_name, test_content):
        """Test print on Linux/macOS"""
        try:
            import tempfile
            import os
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(f"{test_content}\n")
                f.write(f"Printer: {printer_name}\n")
                f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                temp_file = f.name

            try:
                result = subprocess.run(['lp', '-d', printer_name, temp_file], capture_output=True)
                return result.returncode == 0
            finally:
                try:
                    os.unlink(temp_file)
                except OSError:
                    pass
        except Exception as e:
            print(f"Error test printing on Unix: {e}")
            return False


def init_printer_routes(app, db, require_permission):
    """Initialize printer management routes"""
    from flask import Blueprint, render_template, request, jsonify
    from flask_login import login_required
    from functools import wraps

    printer_bp = Blueprint('printers', __name__, url_prefix='/printers')

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

    @printer_bp.route('/manage')
    @auth_required('manage_settings')
    def manage():
        """Printer management page"""
        return render_template('printers/manage.html')

    @printer_bp.route('/api/list')
    @login_required
    def api_list():
        """API: List all printers"""
        manager = PrinterManager()
        printers = manager.list_printers()
        default_printer = manager.get_default_printer()

        return jsonify({
            'success': True,
            'printers': printers,
            'default': default_printer
        })

    @printer_bp.route('/api/set-default', methods=['POST'])
    @auth_required('manage_settings')
    def api_set_default():
        """API: Set default printer"""
        data = request.get_json()
        printer_name = data.get('printer_name')

        if not printer_name:
            return jsonify({'success': False, 'error': 'Printer name is required'}), 400

        manager = PrinterManager()
        try:
            success = manager.set_default_printer(printer_name)
        except ValueError as e:
            return jsonify({'success': False, 'error': str(e)}), 400

        return jsonify({'success': success})

    @printer_bp.route('/api/test', methods=['POST'])
    @auth_required('manage_settings')
    def api_test():
        """API: Test print"""
        data = request.get_json()
        printer_name = data.get('printer_name')

        if not printer_name:
            return jsonify({'success': False, 'error': 'Printer name is required'}), 400

        manager = PrinterManager()
        try:
            success = manager.test_print(printer_name)
        except ValueError as e:
            return jsonify({'success': False, 'error': str(e)}), 400

        return jsonify({'success': success})

    app.register_blueprint(printer_bp)
