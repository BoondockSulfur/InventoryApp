"""
Log Management Utility for InventoryApp

Features:
- View logs
- Delete logs
- Download logs
- Rotate logs
- Filter logs by date/level
"""

import os
import glob
from datetime import datetime, timedelta
from pathlib import Path
import gzip
import shutil

class LogManager:
    """Manage application logs"""

    def __init__(self, log_dir='instance', archive_dir='instance/archives'):
        self.log_dir = Path(log_dir)
        self.archive_dir = Path(archive_dir)
        self.archive_dir.mkdir(exist_ok=True)

    def get_log_files(self):
        """Get list of all log files"""
        log_files = []

        for ext in ['*.log', '*.log.*']:
            for log_file in self.log_dir.glob(ext):
                if log_file.is_file():
                    stat = log_file.stat()
                    log_files.append({
                        'name': log_file.name,
                        'path': str(log_file),
                        'size': stat.st_size,
                        'size_mb': round(stat.st_size / 1024 / 1024, 2),
                        'modified': datetime.fromtimestamp(stat.st_mtime),
                        'modified_str': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })

        return sorted(log_files, key=lambda x: x['modified'], reverse=True)

    def read_log(self, filename, lines=100, tail=True):
        """
        Read log file

        Args:
            filename: Name of log file
            lines: Number of lines to read
            tail: If True, read last N lines; if False, read first N lines
        """
        log_path = self.log_dir / filename

        if not log_path.exists():
            return {'error': 'Log file not found'}

        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()

            if tail:
                selected_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
            else:
                selected_lines = all_lines[:lines]

            return {
                'filename': filename,
                'total_lines': len(all_lines),
                'displayed_lines': len(selected_lines),
                'content': ''.join(selected_lines)
            }

        except Exception as e:
            return {'error': f'Failed to read log: {str(e)}'}

    def delete_log(self, filename):
        """
        Delete a log file

        Args:
            filename: Name of log file to delete

        Returns:
            Success/error dict
        """
        log_path = self.log_dir / filename

        if not log_path.exists():
            return {'success': False, 'error': 'Log file not found'}

        # Safety check: don't delete files outside log directory
        if not str(log_path.resolve()).startswith(str(self.log_dir.resolve())):
            return {'success': False, 'error': 'Invalid file path'}

        try:
            # Get file size before deletion for reporting
            size = log_path.stat().st_size

            # Delete the file
            log_path.unlink()

            return {
                'success': True,
                'message': f'Log file {filename} deleted',
                'size_freed_mb': round(size / 1024 / 1024, 2)
            }

        except Exception as e:
            return {'success': False, 'error': f'Failed to delete log: {str(e)}'}

    def clear_log(self, filename):
        """
        Clear log file content (truncate to 0 bytes)

        Args:
            filename: Name of log file to clear
        """
        log_path = self.log_dir / filename

        if not log_path.exists():
            return {'success': False, 'error': 'Log file not found'}

        try:
            # Get size before clearing
            size = log_path.stat().st_size

            # Truncate file
            with open(log_path, 'w') as f:
                pass  # Just open and close to truncate

            return {
                'success': True,
                'message': f'Log file {filename} cleared',
                'size_freed_mb': round(size / 1024 / 1024, 2)
            }

        except Exception as e:
            return {'success': False, 'error': f'Failed to clear log: {str(e)}'}

    def archive_log(self, filename):
        """
        Archive a log file (compress and move to archive directory)

        Args:
            filename: Name of log file to archive
        """
        log_path = self.log_dir / filename

        if not log_path.exists():
            return {'success': False, 'error': 'Log file not found'}

        try:
            # Create archive filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            archive_name = f"{filename}.{timestamp}.gz"
            archive_path = self.archive_dir / archive_name

            # Compress and save
            with open(log_path, 'rb') as f_in:
                with gzip.open(archive_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # Get sizes
            original_size = log_path.stat().st_size
            archive_size = archive_path.stat().st_size

            # Delete original
            log_path.unlink()

            return {
                'success': True,
                'message': f'Log archived to {archive_name}',
                'original_size_mb': round(original_size / 1024 / 1024, 2),
                'archive_size_mb': round(archive_size / 1024 / 1024, 2),
                'compression_ratio': round((1 - archive_size / original_size) * 100, 1)
            }

        except Exception as e:
            return {'success': False, 'error': f'Failed to archive log: {str(e)}'}

    def delete_old_logs(self, days=30):
        """
        Delete logs older than specified days

        Args:
            days: Delete logs older than this many days
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        deleted_files = []
        total_size_freed = 0

        for log_file in self.get_log_files():
            if log_file['modified'] < cutoff_date:
                result = self.delete_log(log_file['name'])
                if result.get('success'):
                    deleted_files.append(log_file['name'])
                    total_size_freed += log_file['size']

        return {
            'success': True,
            'deleted_count': len(deleted_files),
            'deleted_files': deleted_files,
            'size_freed_mb': round(total_size_freed / 1024 / 1024, 2)
        }

    def get_log_stats(self):
        """Get statistics about all logs"""
        log_files = self.get_log_files()

        total_size = sum(f['size'] for f in log_files)

        return {
            'total_files': len(log_files),
            'total_size_mb': round(total_size / 1024 / 1024, 2),
            'files': log_files
        }


def init_log_routes(app, db):
    """Initialize log management routes"""
    from flask import request, jsonify, send_file
    from flask_login import login_required, current_user
    import io

    log_manager = LogManager()

    def require_admin(f):
        """Decorator to require admin role"""
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(current_user, 'role') or current_user.role != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            return f(*args, **kwargs)
        return decorated_function

    @app.route('/api/logs', methods=['GET'])
    @login_required
    @require_admin
    def list_logs():
        """List all log files"""
        stats = log_manager.get_log_stats()
        return jsonify(stats)

    @app.route('/api/logs/<filename>', methods=['GET'])
    @login_required
    @require_admin
    def view_log(filename):
        """View log file content"""
        lines = request.args.get('lines', 100, type=int)
        tail = request.args.get('tail', 'true').lower() == 'true'

        result = log_manager.read_log(filename, lines=lines, tail=tail)
        return jsonify(result)

    @app.route('/api/logs/<filename>/download', methods=['GET'])
    @login_required
    @require_admin
    def download_log(filename):
        """Download log file"""
        log_path = log_manager.log_dir / filename

        if not log_path.exists():
            return jsonify({'error': 'Log file not found'}), 404

        return send_file(
            log_path,
            as_attachment=True,
            download_name=filename,
            mimetype='text/plain'
        )

    @app.route('/api/logs/<filename>', methods=['DELETE'])
    @login_required
    @require_admin
    def delete_log(filename):
        """Delete a log file"""
        result = log_manager.delete_log(filename)

        if result.get('success'):
            # Log the action
            app.logger.info(f"User {current_user.username} deleted log file: {filename}")
            return jsonify(result)
        else:
            return jsonify(result), 400

    @app.route('/api/logs/<filename>/clear', methods=['POST'])
    @login_required
    @require_admin
    def clear_log(filename):
        """Clear log file content"""
        result = log_manager.clear_log(filename)

        if result.get('success'):
            app.logger.info(f"User {current_user.username} cleared log file: {filename}")
            return jsonify(result)
        else:
            return jsonify(result), 400

    @app.route('/api/logs/<filename>/archive', methods=['POST'])
    @login_required
    @require_admin
    def archive_log(filename):
        """Archive a log file"""
        result = log_manager.archive_log(filename)

        if result.get('success'):
            app.logger.info(f"User {current_user.username} archived log file: {filename}")
            return jsonify(result)
        else:
            return jsonify(result), 400

    @app.route('/api/logs/cleanup', methods=['POST'])
    @login_required
    @require_admin
    def cleanup_logs():
        """Delete old log files"""
        days = request.json.get('days', 30) if request.is_json else 30

        result = log_manager.delete_old_logs(days=days)
        app.logger.info(f"User {current_user.username} cleaned up logs older than {days} days")

        return jsonify(result)

    app.logger.info("✅ Log Management routes initialized")
