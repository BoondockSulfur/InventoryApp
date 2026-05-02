# -*- coding: utf-8 -*-
"""
Integration Marketplace for InventoryApp
Provides plugin architecture for third-party integrations
"""

import json
import hmac
import hashlib
from datetime import datetime
from flask import request, jsonify
import requests


class IntegrationPlugin:
    """Base class for integration plugins"""

    def __init__(self, name, config):
        self.name = name
        self.config = config
        self.enabled = config.get('enabled', False)

    def on_item_created(self, item_data):
        """Called when a new item is created"""
        pass

    def on_item_updated(self, item_data):
        """Called when an item is updated"""
        pass

    def on_item_deleted(self, item_id):
        """Called when an item is deleted"""
        pass

    def on_loan_created(self, loan_data):
        """Called when a new loan is created"""
        pass

    def on_loan_returned(self, loan_data):
        """Called when a loan is returned"""
        pass


class WebhookIntegration(IntegrationPlugin):
    """Webhook integration - sends HTTP requests on events"""

    def __init__(self, config):
        super().__init__('webhook', config)
        self.webhook_url = config.get('webhook_url')
        self.secret = config.get('secret')

    def _send_webhook(self, event_type, data):
        """Send webhook with HMAC signature"""
        if not self.enabled or not self.webhook_url:
            return

        payload = {
            'event': event_type,
            'timestamp': datetime.utcnow().isoformat(),
            'data': data
        }

        payload_json = json.dumps(payload)

        headers = {'Content-Type': 'application/json'}

        # Add HMAC signature if secret is configured
        if self.secret:
            signature = hmac.new(
                self.secret.encode(),
                payload_json.encode(),
                hashlib.sha256
            ).hexdigest()
            headers['X-Webhook-Signature'] = f'sha256={signature}'

        try:
            response = requests.post(
                self.webhook_url,
                data=payload_json,
                headers=headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Webhook error: {e}")
            return False

    def on_item_created(self, item_data):
        self._send_webhook('item.created', item_data)

    def on_item_updated(self, item_data):
        self._send_webhook('item.updated', item_data)

    def on_item_deleted(self, item_id):
        self._send_webhook('item.deleted', {'id': item_id})

    def on_loan_created(self, loan_data):
        self._send_webhook('loan.created', loan_data)

    def on_loan_returned(self, loan_data):
        self._send_webhook('loan.returned', loan_data)


class SlackIntegration(IntegrationPlugin):
    """Slack integration - posts notifications to Slack"""

    def __init__(self, config):
        super().__init__('slack', config)
        self.webhook_url = config.get('slack_webhook_url')
        self.channel = config.get('channel', '#inventory')

    def _send_slack_message(self, message):
        """Send message to Slack"""
        if not self.enabled or not self.webhook_url:
            return

        payload = {
            'channel': self.channel,
            'text': message,
            'username': 'InventoryApp',
            'icon_emoji': ':package:'
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Slack error: {e}")
            return False

    def on_item_created(self, item_data):
        message = f"📦 New item created: *{item_data.get('name')}*"
        self._send_slack_message(message)

    def on_loan_created(self, loan_data):
        message = f"🔄 Item borrowed: *{loan_data.get('item_name')}* by {loan_data.get('borrower_name')}"
        self._send_slack_message(message)

    def on_loan_returned(self, loan_data):
        message = f"✅ Item returned: *{loan_data.get('item_name')}*"
        self._send_slack_message(message)


class MSTeamsIntegration(IntegrationPlugin):
    """Microsoft Teams integration"""

    def __init__(self, config):
        super().__init__('msteams', config)
        self.webhook_url = config.get('teams_webhook_url')

    def _send_teams_message(self, title, text, color="0078D4"):
        """Send adaptive card to Teams"""
        if not self.enabled or not self.webhook_url:
            return

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": title,
            "themeColor": color,
            "title": title,
            "text": text
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Teams error: {e}")
            return False

    def on_item_created(self, item_data):
        self._send_teams_message(
            "New Item Created",
            f"**{item_data.get('name')}** has been added to inventory",
            "28A745"
        )

    def on_loan_created(self, loan_data):
        self._send_teams_message(
            "Item Borrowed",
            f"**{loan_data.get('item_name')}** borrowed by {loan_data.get('borrower_name')}",
            "FFC107"
        )


class EmailIntegration(IntegrationPlugin):
    """Email notification integration"""

    def __init__(self, config, mail):
        super().__init__('email', config)
        self.mail = mail
        self.recipients = config.get('recipients', [])

    def _send_email(self, subject, body):
        """Send email notification"""
        if not self.enabled or not self.recipients:
            return

        from flask_mail import Message

        try:
            msg = Message(
                subject=f"[InventoryApp] {subject}",
                recipients=self.recipients,
                body=body
            )
            self.mail.send(msg)
            return True
        except Exception as e:
            print(f"Email error: {e}")
            return False

    def on_item_created(self, item_data):
        self._send_email(
            "New Item Created",
            f"A new item has been added:\n\nName: {item_data.get('name')}\nSerial: {item_data.get('serial', 'N/A')}"
        )

    def on_loan_created(self, loan_data):
        self._send_email(
            "New Loan Created",
            f"Item borrowed:\n\nItem: {loan_data.get('item_name')}\nBorrower: {loan_data.get('borrower_name')}\nDue: {loan_data.get('due_date')}"
        )


class IntegrationManager:
    """Manages all integrations"""

    def __init__(self, app, db, mail=None):
        self.app = app
        self.db = db
        self.mail = mail
        self.plugins = []
        self._initialized = False

    def _ensure_initialized(self):
        """Lazy initialization - load integrations on first use"""
        if self._initialized:
            return

        with self.app.app_context():
            self._load_integrations(self.mail)
            self._initialized = True

    def _load_integrations(self, mail):
        """Load enabled integrations from database"""
        from app import ModuleSetting

        # Webhook Integration
        webhook_enabled = self._get_setting('integration_webhook_enabled')
        if webhook_enabled == 'true':
            webhook_config = {
                'enabled': True,
                'webhook_url': self._get_setting('integration_webhook_url'),
                'secret': self._get_setting('integration_webhook_secret')
            }
            self.plugins.append(WebhookIntegration(webhook_config))

        # Slack Integration
        slack_enabled = self._get_setting('integration_slack_enabled')
        if slack_enabled == 'true':
            slack_config = {
                'enabled': True,
                'slack_webhook_url': self._get_setting('integration_slack_webhook'),
                'channel': self._get_setting('integration_slack_channel', '#inventory')
            }
            self.plugins.append(SlackIntegration(slack_config))

        # MS Teams Integration
        teams_enabled = self._get_setting('integration_teams_enabled')
        if teams_enabled == 'true':
            teams_config = {
                'enabled': True,
                'teams_webhook_url': self._get_setting('integration_teams_webhook')
            }
            self.plugins.append(MSTeamsIntegration(teams_config))

        # Email Integration
        email_enabled = self._get_setting('integration_email_enabled')
        if email_enabled == 'true' and mail:
            email_config = {
                'enabled': True,
                'recipients': self._get_setting('integration_email_recipients', '').split(',')
            }
            self.plugins.append(EmailIntegration(email_config, mail))

    def _get_setting(self, key, default=None):
        """Get module setting from database"""
        from app import ModuleSetting

        setting = self.db.session.query(ModuleSetting).filter_by(
            key=key,
            user_id=None
        ).first()

        return setting.value if setting else default

    def trigger_event(self, event_type, data):
        """Trigger event on all enabled plugins"""
        self._ensure_initialized()

        for plugin in self.plugins:
            if not plugin.enabled:
                continue

            try:
                if event_type == 'item.created':
                    plugin.on_item_created(data)
                elif event_type == 'item.updated':
                    plugin.on_item_updated(data)
                elif event_type == 'item.deleted':
                    plugin.on_item_deleted(data)
                elif event_type == 'loan.created':
                    plugin.on_loan_created(data)
                elif event_type == 'loan.returned':
                    plugin.on_loan_returned(data)
            except Exception as e:
                self.app.logger.error(f"Integration error in {plugin.name}: {e}")

    def add_plugin(self, plugin):
        """Add custom plugin"""
        self._ensure_initialized()
        self.plugins.append(plugin)

    def remove_plugin(self, name):
        """Remove plugin by name"""
        self._ensure_initialized()
        self.plugins = [p for p in self.plugins if p.name != name]

    def get_plugin(self, name):
        """Get plugin by name"""
        self._ensure_initialized()
        for plugin in self.plugins:
            if plugin.name == name:
                return plugin
        return None

    def list_plugins(self):
        """List all plugins"""
        self._ensure_initialized()
        return [
            {
                'name': p.name,
                'enabled': p.enabled
            }
            for p in self.plugins
        ]
