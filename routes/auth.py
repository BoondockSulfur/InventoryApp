# -*- coding: utf-8 -*-
"""
Authentication Routes Blueprint
All authentication-related routes for InventoryApp
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, current_user, login_required
from flask_mail import Message
from functools import wraps
import os
import uuid

# Create auth blueprint
auth_bp = Blueprint('auth', __name__)


def init_auth_routes(app, db, mail, limiter, OAUTH_AVAILABLE, oauth, SAML_AVAILABLE):
    """Initialize authentication routes with app context"""

    # Import models inside function to avoid circular imports
    from app import User, UserRole, Setting, log_action
    from forms import LoginForm, InitialSetupForm, ResetPasswordRequestForm, ResetPasswordForm

    # Import SAML if available
    if SAML_AVAILABLE:
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth
        except ImportError:
            SAML_AVAILABLE = False

    # ─── SAML Helper Functions ────────────────────────────────────────────

    def prepare_saml_request(flask_request):
        """Bereitet Flask Request für python3-saml vor"""
        return {
            'https': 'on' if flask_request.scheme == 'https' else 'off',
            'http_host': flask_request.host,
            'script_name': flask_request.path,
            'get_data': flask_request.args.copy(),
            'post_data': flask_request.form.copy()
        }

    def get_saml_settings():
        """Lädt SAML Einstellungen aus Environment oder Datenbank"""
        return {
            'strict': True,
            'debug': app.debug,
            'sp': {
                'entityId': os.environ.get('SAML_SP_ENTITY_ID', request.url_root),
                'assertionConsumerService': {
                    'url': url_for('auth.saml_acs', _external=True),
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
                },
                'singleLogoutService': {
                    'url': url_for('auth.saml_logout', _external=True) if 'saml_logout' in app.view_functions else '',
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                },
                'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
                'x509cert': os.environ.get('SAML_SP_CERT', ''),
                'privateKey': os.environ.get('SAML_SP_KEY', '')
            },
            'idp': {
                'entityId': os.environ.get('SAML_IDP_ENTITY_ID', ''),
                'singleSignOnService': {
                    'url': os.environ.get('SAML_IDP_SSO_URL', ''),
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                },
                'singleLogoutService': {
                    'url': os.environ.get('SAML_IDP_SLO_URL', ''),
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                },
                'x509cert': os.environ.get('SAML_IDP_CERT', '')
            }
        }

    def send_reset_email(user):
        """Send password reset email"""
        if not mail:
            app.logger.warning("Mail service not available, cannot send reset email")
            return

        token = user.get_reset_token()
        msg = Message('Password Reset Request',
                      sender=app.config.get('MAIL_DEFAULT_SENDER', 'noreply@inventoryapp.com'),
                      recipients=[user.email])
        msg.body = f'''To reset your password, visit the following link:
{url_for('auth.reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
        try:
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Failed to send reset email: {e}")

    # ─── Login Route ──────────────────────────────────────────────────────

    @auth_bp.route('/login', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def login():
        """Standard login"""
        # Check if any admin exists
        admin_exists = User.query.filter_by(role=UserRole.ADMIN).first() is not None
        if not admin_exists:
            return redirect(url_for('auth.initial_setup'))

        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        form = LoginForm()
        if form.validate_on_submit():
            usr = User.query.filter_by(username=form.username.data).first()
            if not usr or not usr.check_password(form.password.data):
                app.logger.warning(f'Failed login attempt for username: {form.username.data}')
                flash('Ungültiger Benutzername oder Passwort', 'danger')
                return redirect(url_for('auth.login'))
            app.logger.info(f'Successful login for user: {usr.username}')
            login_user(usr)
            return redirect(url_for('dashboard'))

        # Check which OAuth providers are configured
        oauth_providers = []
        if OAUTH_AVAILABLE and oauth:
            if os.environ.get('GOOGLE_CLIENT_ID'):
                oauth_providers.append(('google', 'Google', 'bi-google'))
            if os.environ.get('MICROSOFT_CLIENT_ID'):
                oauth_providers.append(('microsoft', 'Microsoft', 'bi-microsoft'))
            if os.environ.get('GITHUB_CLIENT_ID'):
                oauth_providers.append(('github', 'GitHub', 'bi-github'))

        return render_template('login.html', form=form, oauth_providers=oauth_providers)

    # ─── OAuth Routes ─────────────────────────────────────────────────────

    @auth_bp.route('/oauth/<provider>')
    def oauth_login(provider):
        """Initiiert OAuth Login Flow"""
        if not OAUTH_AVAILABLE or not oauth:
            flash('OAuth ist nicht verfügbar', 'warning')
            return redirect(url_for('auth.login'))

        if provider not in ['google', 'microsoft', 'github']:
            flash('Ungültiger OAuth Provider', 'danger')
            return redirect(url_for('auth.login'))

        try:
            client = oauth.create_client(provider)
            redirect_uri = url_for('auth.oauth_callback', provider=provider, _external=True)
            return client.authorize_redirect(redirect_uri)
        except Exception as e:
            app.logger.error(f'OAuth {provider} login failed: {e}')
            flash(f'OAuth Login fehlgeschlagen: {str(e)}', 'danger')
            return redirect(url_for('auth.login'))

    @auth_bp.route('/oauth/<provider>/callback')
    def oauth_callback(provider):
        """Callback für OAuth Provider"""
        if not OAUTH_AVAILABLE or not oauth:
            flash('OAuth ist nicht verfügbar', 'warning')
            return redirect(url_for('auth.login'))

        try:
            client = oauth.create_client(provider)
            token = client.authorize_access_token()

            # Get user info from provider
            if provider == 'google':
                user_info = token.get('userinfo')
                email = user_info.get('email')
                username = user_info.get('name') or email.split('@')[0]
            elif provider == 'microsoft':
                user_info = client.get('https://graph.microsoft.com/v1.0/me').json()
                email = user_info.get('mail') or user_info.get('userPrincipalName')
                username = user_info.get('displayName') or email.split('@')[0]
            elif provider == 'github':
                user_info = client.get('user').json()
                email = user_info.get('email')
                if not email:
                    # GitHub may not provide email in profile, fetch from emails endpoint
                    emails = client.get('user/emails').json()
                    primary_email = next((e for e in emails if e.get('primary')), None)
                    email = primary_email.get('email') if primary_email else None
                username = user_info.get('login')
            else:
                flash('Ungültiger OAuth Provider', 'danger')
                return redirect(url_for('auth.login'))

            if not email:
                flash('E-Mail konnte nicht vom OAuth Provider abgerufen werden', 'danger')
                return redirect(url_for('auth.login'))

            # Find or create user
            user = User.query.filter_by(email=email).first()
            if not user:
                # Check if OAuth auto-registration is enabled
                auto_register_setting = db.session.get(Setting, 'OAUTH_AUTO_REGISTER')
                auto_register = auto_register_setting and auto_register_setting.value.lower() in ['true', '1', 'yes']

                if not auto_register:
                    flash('Ihr Account existiert noch nicht. Bitte kontaktieren Sie einen Administrator.', 'warning')
                    return redirect(url_for('auth.login'))

                # Auto-create user with default role
                default_role_setting = db.session.get(Setting, 'OAUTH_DEFAULT_ROLE')
                default_role = default_role_setting.value if default_role_setting else 'user'

                user = User(
                    username=username,
                    email=email,
                    role=default_role
                )
                # Set random password for OAuth users (they won't use it)
                user.set_password(uuid.uuid4().hex)
                db.session.add(user)
                db.session.commit()
                app.logger.info(f'OAuth user auto-created: {email} via {provider}')

            login_user(user)
            app.logger.info(f'Successful OAuth login: {email} via {provider}')
            flash(f'Erfolgreich angemeldet via {provider.title()}', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            app.logger.error(f'OAuth {provider} callback failed: {e}')
            flash(f'OAuth Login fehlgeschlagen: {str(e)}', 'danger')
            return redirect(url_for('auth.login'))

    # ─── SAML Routes ──────────────────────────────────────────────────────

    @auth_bp.route('/saml/login')
    def saml_login():
        """Initiiert SAML SSO Login"""
        if not SAML_AVAILABLE:
            flash('SAML SSO ist nicht verfügbar', 'warning')
            return redirect(url_for('auth.login'))

        try:
            req = prepare_saml_request(request)
            auth = OneLogin_Saml2_Auth(req, get_saml_settings())
            return redirect(auth.login())
        except Exception as e:
            app.logger.error(f'SAML login failed: {e}')
            flash(f'SAML SSO fehlgeschlagen: {str(e)}', 'danger')
            return redirect(url_for('auth.login'))

    @auth_bp.route('/saml/acs', methods=['POST'])
    def saml_acs():
        """SAML Assertion Consumer Service - Callback von IdP"""
        if not SAML_AVAILABLE:
            flash('SAML SSO ist nicht verfügbar', 'warning')
            return redirect(url_for('auth.login'))

        try:
            req = prepare_saml_request(request)
            auth = OneLogin_Saml2_Auth(req, get_saml_settings())
            auth.process_response()

            errors = auth.get_errors()
            if errors:
                app.logger.error(f'SAML errors: {errors}')
                flash(f'SAML Authentication fehlgeschlagen', 'danger')
                return redirect(url_for('auth.login'))

            if not auth.is_authenticated():
                flash('SAML Authentication fehlgeschlagen', 'danger')
                return redirect(url_for('auth.login'))

            # Get user attributes from SAML response
            attributes = auth.get_attributes()
            email = attributes.get('email', [None])[0] or attributes.get('mail', [None])[0]
            username = attributes.get('username', [None])[0] or email.split('@')[0] if email else None

            if not email:
                flash('E-Mail konnte nicht von SAML Provider abgerufen werden', 'danger')
                return redirect(url_for('auth.login'))

            # Find or create user
            user = User.query.filter_by(email=email).first()
            if not user:
                auto_register_setting = db.session.get(Setting, 'SAML_AUTO_REGISTER')
                auto_register = auto_register_setting and auto_register_setting.value.lower() in ['true', '1', 'yes']

                if not auto_register:
                    flash('Ihr Account existiert noch nicht. Bitte kontaktieren Sie einen Administrator.', 'warning')
                    return redirect(url_for('auth.login'))

                default_role_setting = db.session.get(Setting, 'SAML_DEFAULT_ROLE')
                default_role = default_role_setting.value if default_role_setting else 'user'

                user = User(
                    username=username,
                    email=email,
                    role=default_role
                )
                user.set_password(uuid.uuid4().hex)
                db.session.add(user)
                db.session.commit()
                app.logger.info(f'SAML user auto-created: {email}')

            login_user(user)
            app.logger.info(f'Successful SAML login: {email}')
            flash('Erfolgreich via SAML SSO angemeldet', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            app.logger.error(f'SAML ACS failed: {e}')
            flash(f'SAML Authentication fehlgeschlagen: {str(e)}', 'danger')
            return redirect(url_for('auth.login'))

    # ─── Initial Setup ────────────────────────────────────────────────────

    @auth_bp.route('/initial-setup', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def initial_setup():
        """Initial admin account setup"""
        # Check if admin already exists
        admin_exists = User.query.filter_by(role=UserRole.ADMIN).first() is not None
        if admin_exists:
            flash('Admin-Account existiert bereits!', 'info')
            return redirect(url_for('auth.login'))

        form = InitialSetupForm()
        if form.validate_on_submit():
            # Create admin user
            admin = User(
                username=form.username.data,
                email=form.email.data,
                role=UserRole.ADMIN
            )
            admin.set_password(form.password.data)
            db.session.add(admin)
            db.session.commit()
            app.logger.info(f'Initial admin account created: {admin.username}')
            flash('Admin-Account erfolgreich erstellt! Bitte melden Sie sich an.', 'success')
            return redirect(url_for('auth.login'))

        return render_template('initial_setup.html', form=form)

    # ─── Password Reset ───────────────────────────────────────────────────

    @auth_bp.route('/reset-password', methods=['GET', 'POST'])
    @limiter.limit("3 per hour")
    def reset_request():
        """Request password reset"""
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        form = ResetPasswordRequestForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                send_reset_email(user)
            flash('Wenn eine Übereinstimmung gefunden wurde, schicken wir dir einen Link per E-Mail.', 'info')
            return redirect(url_for('auth.login'))

        return render_template('reset_request.html', form=form)

    @auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
    @limiter.limit("3 per hour")
    def reset_token(token):
        """Reset password with token"""
        if current_user.is_authenticated:
            logout_user()

        user = User.verify_reset_token(token)
        if not user:
            flash('Der Link ist ungültig oder abgelaufen.', 'warning')
            return redirect(url_for('auth.reset_request'))

        form = ResetPasswordForm()
        if form.validate_on_submit():
            user.set_password(form.password.data)
            db.session.commit()
            app.logger.info(f'Password reset successful for user: {user.username}')
            flash('Dein Passwort wurde zurückgesetzt. Bitte melde dich mit deinem neuen Passwort an.', 'success')
            return redirect(url_for('auth.login'))

        return render_template('reset_token.html', form=form)

    # ─── Logout ───────────────────────────────────────────────────────────

    @auth_bp.route('/logout')
    @login_required
    def logout():
        """Logout current user"""
        logout_user()
        return redirect(url_for('auth.login'))

    # ─── LDAP Login ───────────────────────────────────────────────────────

    @auth_bp.route('/login/ldap', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def login_ldap():
        """LDAP Login"""
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            try:
                # LDAP-Authentifizierung (Platzhalter)
                # import ldap
                # conn = ldap.initialize('ldap://your-ldap-server')
                # conn.simple_bind_s(f'cn={username},dc=example,dc=com', password)

                # Bei erfolgreicher LDAP-Auth: User in lokaler DB suchen/erstellen
                user = User.query.filter_by(username=username).first()

                if not user:
                    # Erstelle neuen User aus LDAP
                    user = User(
                        username=username,
                        email=f'{username}@example.com',  # Von LDAP holen
                        is_ldap_user=True,
                        ldap_dn=f'cn={username},dc=example,dc=com',
                        role=UserRole.MITARBEITER
                    )
                    user.set_password(str(uuid.uuid4()))  # Random PW, wird nicht benutzt
                    db.session.add(user)
                    db.session.commit()

                login_user(user)
                log_action('ldap_login', 'user', user.id)

                flash('Erfolgreich angemeldet via LDAP', 'success')
                return redirect(url_for('dashboard'))

            except Exception as e:
                app.logger.error(f'LDAP login failed: {e}')
                flash('LDAP-Anmeldung fehlgeschlagen', 'danger')

        return render_template('login_ldap.html')

    # Register blueprint
    app.register_blueprint(auth_bp)

    # Also register root route for login
    @app.route('/')
    def index():
        """Root route redirects to login or dashboard"""
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('auth.login'))

    app.logger.info("✅ Auth routes blueprint registered")
