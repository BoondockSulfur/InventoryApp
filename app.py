# -*- coding: utf-8 -*-
import os
import uuid
import socket
import csv, subprocess
import logging
from logging.handlers import RotatingFileHandler
from io import BytesIO
from datetime import date, datetime
from flask import (
    Flask, send_file, render_template, redirect, url_for,
    flash, request, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user, UserMixin
)
from flask_mail import Mail, Message
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import (
    StringField, PasswordField, SubmitField,
    SelectField, DateField, EmailField,
    IntegerField, BooleanField, TextAreaField
)
from wtforms.validators import (
    DataRequired, Length, Email, EqualTo, ValidationError
)
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from weasyprint import HTML
from dotenv import load_dotenv
from functools import wraps
from flask import abort
from flask import current_app, g
from itsdangerous import URLSafeTimedSerializer as Serializer
from sqlalchemy import or_

# ─── Umgebungsvariablen laden ─────────────────────────────────────────────────
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER   = os.environ.get('MAIL_SERVER')
    MAIL_PORT     = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS  = os.environ.get('MAIL_USE_TLS', 'false').lower() in ['true','1','yes']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ADMINS        = os.environ.get('ADMIN_EMAIL','').split(',') if os.environ.get('ADMIN_EMAIL') else []

    PRINTER_IP   = os.environ.get('PRINTER_IP')
    PRINTER_PORT = int(os.environ.get('PRINTER_PORT', 9100))
    WARRANTY_CSV_DIR = os.environ.get('WARRANTY_CSV_DIR')
    WARRANTY_CLI_CMD = os.environ.get('WARRANTY_CLI_CMD', 'DellWarranty-CLI.exe')
    DELL_CLIENT_ID     = os.environ.get('DELL_CLIENT_ID')
    DELL_CLIENT_SECRET = os.environ.get('DELL_CLIENT_SECRET')

# ─── App-Initialisierung ──────────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)
if not app.debug:
    log_path = app.config.get(
        'ERROR_LOG_PATH',
        os.path.join(app.instance_path, 'error.log')
    )
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    fh = RotatingFileHandler(log_path, maxBytes=10*1024*1024, backupCount=3)
    fh.setLevel(logging.ERROR)
    app.logger.addHandler(fh)
app.jinja_env.globals['date'] = date
csrf  = CSRFProtect(app)
db    = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'
role_permissions = db.Table(
    'role_permissions',
    db.Column('role_name',       db.String(20), db.ForeignKey('role.name'),       primary_key=True),
    db.Column('permission_name', db.String(50), db.ForeignKey('permission.name'), primary_key=True)
)

# User loader für Flask-Login
@login.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

mail      = Mail(app)
scheduler = BackgroundScheduler()

# ─── Datenbank-Modelle ────────────────────────────────────────────────────────
class Role(db.Model):
    __tablename__ = 'role'
    name        = db.Column(db.String(20), primary_key=True)
    permissions = db.relationship(
        'Permission',
        secondary=role_permissions,
        back_populates='roles'
    )

class Permission(db.Model):
    __tablename__ = 'permission'
    name        = db.Column(db.String(50), primary_key=True)
    description = db.Column(db.String(200))
    roles       = db.relationship(
        'Role',
        secondary=role_permissions,
        back_populates='permissions'
    )

class Setting(db.Model):
    """
    Schlüssel–Wert Paare für konfigurierbare System-Einstellungen.
    """
    key   = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(200), nullable=False)

class User(UserMixin, db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role          = db.Column(db.String(20), nullable=False, default='verwaltung')  # admin / verwaltung
    group_number  = db.Column(db.String(32), nullable=True)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    def get_reset_token(self, expires_sec=3600):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['user_id'])

class Item(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(128), nullable=False)
    serial      = db.Column(db.String(64), unique=True, nullable=False)
    location    = db.Column(db.String(128))
    note        = db.Column(db.Text)
    category    = db.Column(db.String(32), nullable=False, default='other')
    is_borrowed = db.Column(db.Boolean, default=False)
    defective   = db.Column(db.Boolean, default=False)

class Loan(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    item_id      = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    borrower_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    loan_date    = db.Column(db.Date, default=date.today, nullable=False)
    due_date     = db.Column(db.Date, nullable=False)
    return_date  = db.Column(db.Date)
    borrower     = db.relationship('User', backref='loans')
    item         = db.relationship('Item', backref='loans')
    borrower     = db.relationship('User', backref='loans')

class Ticket(db.Model):
    __tablename__ = 'ticket'
    id           = db.Column(db.Integer, primary_key=True)
    title        = db.Column(db.String(150), nullable=False)
    description  = db.Column(db.Text, nullable=False)
    status       = db.Column(db.String(20), nullable=False, default='open')  # open, in_progress, closed
    created_at   = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user         = db.relationship('User', backref='tickets')
    responses    = db.relationship('TicketResponse', backref='ticket', cascade='all, delete-orphan')

class TicketResponse(db.Model):
    __tablename__ = 'ticket_response'
    id           = db.Column(db.Integer, primary_key=True)
    ticket_id    = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user         = db.relationship('User', backref='ticket_responses')
    message      = db.Column(db.Text, nullable=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class AuditLog(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user       = db.relationship('User', backref='audit_logs')
    endpoint   = db.Column(db.String(200), nullable=False)
    method     = db.Column(db.String(10), nullable=False)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# ─── Formulare ─────────────────────────────────────────────────────────────────
class DummyForm(FlaskForm):
    borrower_name = StringField('Entleiher', validators=[DataRequired()])
    due_date      = DateField('Rückgabedatum', format='%Y-%m-%d', validators=[DataRequired()])
    submit        = SubmitField('Ausleihen')

class LoginForm(FlaskForm):
    username = StringField('Benutzername', validators=[DataRequired(), Length(min=4, max=64)])
    password = PasswordField('Passwort', validators=[DataRequired()])
    submit   = SubmitField('Anmelden')

class ResetPasswordRequestForm(FlaskForm):
    email  = EmailField('E-Mail', validators=[DataRequired(), Email()])
    submit = SubmitField('Link zum Zurücksetzen senden')

class ResetPasswordForm(FlaskForm):
    password  = PasswordField('Neues Passwort', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Passwort wiederholen',
                              validators=[DataRequired(), EqualTo('password')])
    submit    = SubmitField('Passwort zurücksetzen')

class RegistrationForm(FlaskForm):
    username  = StringField('Benutzername', validators=[DataRequired(), Length(min=4, max=64)])
    email     = EmailField('E-Mail', validators=[DataRequired(), Email()])
    password  = PasswordField('Passwort', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField(
        'Passwort wiederholen',
        validators=[DataRequired(), EqualTo('password', message='Passwörter müssen übereinstimmen')]
    )
    role   = SelectField('Rolle', choices=[('admin','Admin'),('verwaltung','Verwaltung'), ('mitarbeiter', 'Mitarbeiter'), ('kunde', 'Kunde')], default='kunde')
    group_number = StringField('Gruppen-Nr. (nur für Kunden)', validators=[Length(max=32)])
    submit = SubmitField('Benutzer erstellen')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Dieser Benutzername ist bereits vergeben.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Diese E-Mail-Adresse wird bereits verwendet.')

class ItemForm(FlaskForm):
    name     = StringField('Bezeichnung', validators=[DataRequired(), Length(max=128)])
    serial   = StringField('Seriennummer', validators=[DataRequired(), Length(max=64)])
    location = StringField('Standort', validators=[Length(max=128)])
    note      = TextAreaField('Notiz', validators=[Length(max=500)])
    category = SelectField('Kategorie',choices=[('laptop','Laptop'),('other','Sonstiges')],default='other')
    submit   = SubmitField('Speichern')

    def validate_serial(self, serial):
        if Item.query.filter_by(serial=serial.data).first():
            raise ValidationError('Diese Seriennummer existiert bereits.')

class BorrowerForm(FlaskForm):
    name   = StringField('Name', validators=[DataRequired(), Length(max=128)])
    email  = EmailField('E-Mail', validators=[DataRequired(), Email()])
    type   = SelectField('Typ', choices=[('employee','Mitarbeitende'),('participant','Teilnehmende')])
    submit = SubmitField('Speichern')

class ReturnForm(FlaskForm):
    submit = SubmitField('Rückgabe verbuchen')

class TicketForm(FlaskForm):
    title       = StringField('Betreff', validators=[DataRequired(), Length(max=150)])
    description = StringField('Beschreibung', validators=[DataRequired()])
    submit      = SubmitField('Ticket abschicken')

class ResponseForm(FlaskForm):
    message = StringField('Antwort', validators=[DataRequired()])
    submit  = SubmitField('Nachricht senden')

class StatusForm(FlaskForm):
    status = SelectField(
        'Status',
        choices=[('open','Open'),
                 ('in_progress','In Progress'),
                 ('closed','Closed')],
        validators=[DataRequired()]
    )
    submit = SubmitField('Aktualisieren')

class EditUserForm(FlaskForm):
    username     = StringField('Benutzername', validators=[DataRequired(), Length(min=4, max=64)])
    email        = EmailField('E-Mail', validators=[DataRequired(), Email()])
    role         = SelectField('Rolle', choices=[
                        ('admin','Admin'),
                        ('verwaltung','Verwaltung'),
                        ('mitarbeiter','Mitarbeiter'),
                        ('kunde','Kunde')
                    ])
    group_number = StringField('Gruppen-Nr. (nur für Kunden)', validators=[Length(max=32)])
    submit       = SubmitField('Speichern')

class SettingsForm(FlaskForm):
    mail_server   = StringField('SMTP Server', validators=[DataRequired()])
    mail_port     = IntegerField('SMTP Port', validators=[DataRequired()])
    mail_use_tls  = BooleanField('TLS verwenden')
    mail_username = StringField('SMTP Username', validators=[DataRequired()])
    mail_password = PasswordField('SMTP Passwort', validators=[DataRequired()])
    admins        = StringField('Admin E-Mails (mit „;“ getrennt)')
    printer_ip    = StringField('Drucker-IP')
    printer_port  = IntegerField('Drucker-Port', validators=[DataRequired()])
    dell_client_id     = StringField('Dell API Client ID', validators=[DataRequired(), Length(max=128)])
    dell_client_secret = PasswordField('Dell API Client Secret', validators=[DataRequired(), Length(max=128)])
    submit        = SubmitField('Speichern')

# ─── Hilfsfunktionen ──────────────────────────────────────────────────────────
def fetch_dell_license(serial):
    # Platzhalter für Dell-API
    return {'status': 'Aktiv', 'expiry': date(2025,12,31)}

def send_contract_email(loan):
    borrower = loan.borrower
    item     = loan.item

    # Wähle das Template je nach Rolle
    if borrower.role == 'mitarbeiter':
        tpl = 'contract_employee.html'
    else:
        tpl = 'contract_customer.html'

    # Rendern und PDF erzeugen
    html    = render_template(tpl, loan=loan, borrower=borrower, item=item)
    pdf_buf = BytesIO()
    HTML(string=html).write_pdf(target=pdf_buf)
    pdf_buf.seek(0)

    # E-Mail zusammenstellen
    msg = Message(
        'Ihr Leihvertrag',
        sender    = app.config['MAIL_USERNAME'],
        recipients= [borrower.email]
    )
    msg.body = 'Im Anhang finden Sie Ihren Leihvertrag.'
    filename = f'Leihvertrag_{loan.id}.pdf'
    msg.attach(filename, 'application/pdf', pdf_buf.read())

    # Abschicken
    try:
        mail.send(msg)
    except Exception as e:
        app.logger.error(f'Fehler beim Senden der Vertrags-Mail an {borrower.email}: {e}')

def send_reset_email(user):
    token = user.get_reset_token()
    reset_url = url_for('reset_token', token=token, _external=True)
    msg = Message('Passwort zurücksetzen',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'''Hallo {user.username},

klicke auf den folgenden Link, um dein Passwort zurückzusetzen:
{reset_url}

Falls du diese E-Mail nicht angefordert hast, ignoriere sie bitte.
'''
    mail.send(msg)

def check_overdue():
    today = date.today()
    overdue = Loan.query.filter(Loan.return_date.is_(None), Loan.due_date<today).all()
    for ln in overdue:
        bor = ln.borrower
        it  = ln.item
        nr  = f'{it.name} (SN: {it.serial})'
        # Mail an Entleiher
        m = Message(
            'Erinnerung: Rückgabe überfällig',
            sender=app.config['MAIL_USERNAME'],
            recipients=[bor.email]
        )
        m.body = (
            f'Sie haben {nr} bis {ln.due_date} ausgeliehen. '
            'Bitte geben Sie ihn umgehend zurück.'
        )
        mail.send(m)
        # Mail an Admins
        for adm in app.config['ADMINS']:
            adm_msg = Message(
                'Verzögerung bei Leihübergabe',
                sender=app.config['MAIL_USERNAME'],
                recipients=[adm]
            )
            adm_msg.body = (
                f'{nr} von {bor.name} ist seit {ln.due_date} überfällig.'
            )
            mail.send(adm_msg)

# Scheduler: täglich um 09:00
scheduler.add_job(func=check_overdue, trigger='cron', hour=9, minute=0)
scheduler.start()

# ─── Routen ───────────────────────────────────────────────────────────────────

@app.after_request
def log_audit(response):
    if current_user.is_authenticated:
        a = AuditLog(
            user_id  = current_user.id,
            endpoint = request.path,
            method   = request.method
        )
        db.session.add(a)
        db.session.commit()
    return response

@app.context_processor
def inject_permissions():
    if not current_user.is_authenticated:
        return {}
    role = db.session.get(Role, current_user.role)
    perms = [p.name for p in role.permissions] if role else []
    return dict(permissions=perms)

def requires_permission(perm):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            role = db.session.get(Role, current_user.role)
            if not role or perm not in [p.name for p in role.permissions]:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/generate_serial', methods=['GET'])
@login_required
def generate_serial():
    new_serial = uuid.uuid4().hex[:8].upper()
    zpl = f'^XA^FO50,50^BCN,100,Y,N,N^FD{new_serial}^FS^XZ'
    try:
        with socket.socket() as s:
            s.connect((app.config['PRINTER_IP'], app.config['PRINTER_PORT']))
            s.send(zpl.encode('utf-8'))
    except Exception as e:
        app.logger.error(f'Fehler beim Drucken des Barcodes: {e}')
    return jsonify({'serial': new_serial})

@app.route('/')
@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        usr = User.query.filter_by(username=form.username.data).first()
        if not usr or not usr.check_password(form.password.data):
            flash('Ungültiger Benutzername oder Passwort','danger')
            return redirect(url_for('login'))
        login_user(usr)
        return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/reset_password', methods=['GET','POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash('Wenn eine Übereinstimmung gefunden wurde, schicken wir dir einen Link per E-Mail.','info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET','POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    user = User.verify_reset_token(token)
    if not user:
        flash('Der Link ist ungültig oder abgelaufen.','warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Dein Passwort wurde zurückgesetzt.','success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    total    = Item.query.count()
    borrowed = Item.query.filter_by(is_borrowed=True).count()
    overdue  = Loan.query.filter(Loan.return_date.is_(None), Loan.due_date<date.today()).all()
    return render_template(
        'dashboard.html',
        total_items=total,
        borrowed_items=borrowed,
        overdue_loans=overdue
    )

@app.route('/items')
@login_required
@requires_permission('manage_items')
def items():
    q     = request.args.get('q','')
    query = Item.query
    if current_user.role not in ('admin','verwaltung'):
        flash('Zugriff verweigert','danger')
        my_ids = [ln.item_id for ln in Loan.query.filter_by(borrower_id=current_user.id).all()]
        query  = query.filter(Item.id.in_(my_ids))
    if q:
        query = query.filter(Item.name.ilike(f'%{q}%'))
    lst = query.order_by(Item.is_borrowed.asc(), Item.name.asc()).all()
    return render_template('items.html', items=lst, search=q)

@app.route('/item/add', methods=['GET','POST'])
@login_required
@requires_permission('manage_items')
def add_item():
    if current_user.role not in ('admin','verwaltung'):
        flash('Zugriff verweigert','danger')
        return redirect(url_for('items'))

    form = ItemForm()
    if form.validate_on_submit():
        # 1) Neuen Gegenstand anlegen und speichern
        itm = Item(
            name=form.name.data,
            serial=form.serial.data,
            location=form.location.data,
            category=form.category.data
        )
        db.session.add(itm)
        db.session.commit()
        flash('Gegenstand hinzugefügt','success')

        # 2) Nur für Laptops: Service-Tag in CSV + CLI ausführen
        if itm.category == 'laptop':
            # Arbeitsverzeichnis unter instance/warranty
            csv_dir = app.config.get('WARRANTY_CSV_DIR') \
                      or os.path.join(app.instance_path, 'warranty')
            os.makedirs(csv_dir, exist_ok=True)

            input_csv  = os.path.join(csv_dir, 'Dell-Support.csv')
            output_csv = os.path.join(csv_dir, 'Dell-Support-Ausgabe.csv')

            # Seriennummer anhängen
            with open(input_csv, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([itm.serial])

            # CLI aufrufen
            cli_cmd = app.config.get('WARRANTY_CLI_CMD', 'DellWarranty-CLI.exe')
            try:
                subprocess.run(
                    [cli_cmd, f'/I={input_csv}', f'/E={output_csv}'],
                    check=True
                )
            except subprocess.CalledProcessError as e:
                app.logger.error(f'Warranty-CLI-Fehler (exit {e.returncode})')
            except FileNotFoundError:
                app.logger.error(f'Warranty-CLI nicht gefunden: {cli_cmd}')
            except Exception as e:
                app.logger.error(f'Unerwarteter Fehler bei Warranty-CLI: {e}')

        return redirect(url_for('items'))

    # Bei GET oder ungültigem Formular zurück zum Formular
    return render_template('add_item.html', form=form)

@app.route('/item/<int:item_id>/edit', methods=['GET','POST'])
@login_required
@requires_permission('manage_items')
def edit_item(item_id):
    itm = Item.query.get_or_404(item_id)
    if current_user.role != 'admin':
        abort(403)
    form = ItemForm(obj=itm)
    if form.validate_on_submit():
        form.populate_obj(itm)
        db.session.commit()
        flash('Gegenstand aktualisiert','success')
        return redirect(url_for('item_detail', item_id=itm.id))
    return render_template('edit_item.html', form=form, item=itm)

@app.route('/item/<int:item_id>/delete', methods=['POST'])
@login_required
@requires_permission('manage_items')
def delete_item(item_id):
    itm = Item.query.get_or_404(item_id)
    if current_user.role != 'admin':
        abort(403)
    db.session.delete(itm)
    db.session.commit()
    flash('Gegenstand gelöscht','warning')
    return redirect(url_for('items'))

@app.route('/item/<int:item_id>')
@login_required
@requires_permission('manage_items')
def item_detail(item_id):
    itm         = Item.query.get_or_404(item_id)
    lic         = fetch_dell_license(itm.serial)
    act_loan    = Loan.query.filter_by(item_id=itm.id, return_date=None).first()
    return_form = ReturnForm()
    today       = date.today()
    warranty = None
    if itm.category == 'laptop':
        csv_dir = app.config.get('WARRANTY_CSV_DIR') \
                  or os.path.join(app.instance_path, 'warranty'
        )
        output_csv = os.path.join(csv_dir, 'Dell-Support-Ausgabe.csv')
        try:
            with open(output_csv, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('ServiceTag') == itm.serial:
                        warranty = row
                        break
        except FileNotFoundError:
            warranty = None
    return render_template(
        'item_detail.html',
        item=itm, loan=act_loan, license=lic,
        return_form=return_form, today=today
    )

@app.route('/item/<int:item_id>/loan', methods=['GET','POST'])
@login_required
@requires_permission('manage_items')
def loan_item(item_id):
    # Gegenstand laden oder 404
    itm = Item.query.get_or_404(item_id)

    # Mögliche Entleiher (Mitarbeiter und Kunden)
    borrowers = User.query.filter(
        User.role.in_(['mitarbeiter', 'kunde'])
    ).all()

    # Formular initialisieren
    form = DummyForm()
    if form.validate_on_submit():
        # POST-Logik: ausgewählten User finden
        bor = User.query.filter_by(username=form.borrower_name.data.strip()).first()
        if not bor:
            flash('Entleiher nicht gefunden', 'danger')
            return redirect(url_for('loan_item', item_id=item_id))

        if form.due_date.data < date.today():
            flash('Rückgabedatum in der Vergangenheit', 'warning')
            return redirect(url_for('loan_item', item_id=item_id))

        # Leihvorgang anlegen
        ln = Loan(item_id=itm.id, borrower_id=bor.id, due_date=form.due_date.data)
        itm.is_borrowed = True
        db.session.add(ln)
        db.session.commit()

        flash('Leihvorgang erstellt', 'success')
        send_contract_email(ln)
        return redirect(url_for('item_detail', item_id=item_id))

    # GET-Request oder fehlerhafte POST-Validierung: Formular anzeigen
    return render_template(
        'loan_form.html',
        item=itm,
        borrowers=borrowers,
        form=form
    )

@app.route('/item/<int:item_id>/return', methods=['POST'])
@login_required
def return_item(item_id):
    form = ReturnForm()
    if not form.validate_on_submit():
        flash('Ungültige Anfrage','danger')
        return redirect(url_for('item_detail', item_id=item_id))
    if current_user.role not in ('admin','verwaltung'):
        flash('Zugriff verweigert','danger')
        return redirect(url_for('items'))
    itm = Item.query.get_or_404(item_id)
    ln  = Loan.query.filter_by(item_id=itm.id, return_date=None).first()
    if not ln:
        flash('Kein aktiver Leihvorgang','warning')
        return redirect(url_for('item_detail', item_id=item_id))
    ln.return_date   = date.today()
    itm.is_borrowed = False
    db.session.commit()
    flash('Rückgabe verbucht','success')
    return redirect(url_for('item_detail', item_id=item_id))

@app.route('/item/<int:item_id>/print_label')
@login_required
def print_label(item_id):
    itm = Item.query.get_or_404(item_id)
    zpl = f'^XA^FO50,50^BCN,100,Y,N,N^FD{itm.serial}^FS^XZ'
    try:
        with socket.socket() as s:
            s.connect((app.config['PRINTER_IP'], app.config['PRINTER_PORT']))
            s.send(zpl.encode('utf-8'))
        flash('Label an Drucker gesendet','success')
    except Exception:
        flash('Druck fehlgeschlagen','danger')
    return redirect(url_for('item_detail', item_id=item_id))

@app.route('/item/<int:item_id>/defect', methods=['POST'])
@login_required
def mark_defective(item_id):
    if current_user.role not in ('admin','verwaltung'):
        abort(403)
    itm = Item.query.get_or_404(item_id)
    itm.defective = True
    itm.is_borrowed = True   # gleichzeitig nicht verfügbar
    db.session.commit()
    flash('Gegenstand als defekt markiert','warning')
    return redirect(url_for('item_detail', item_id=item_id))

@app.route('/item/<int:item_id>/repair', methods=['POST'])
@login_required
def mark_repaired(item_id):
    if current_user.role not in ('admin','verwaltung'):
        abort(403)
    itm = Item.query.get_or_404(item_id)
    itm.defective = False
    itm.is_borrowed = False  # wieder verfügbar
    db.session.commit()
    flash('Gegenstand als repariert markiert','success')
    return redirect(url_for('item_detail', item_id=item_id))

@app.route('/loans/active')
@login_required
def active_loans():
    loans = Loan.query.filter_by(return_date=None).all()
    today = date.today()
    return render_template('active_loans.html', loans=loans, today=today)

@app.route('/users')
@login_required
@requires_permission('manage_users')
def users():
    if current_user.role not in ('admin', 'verwaltung'):
        flash('Zugriff verweigert', 'danger')
        return redirect(url_for('dashboard'))
    q = request.args.get('q', '').strip()
    query = User.query
    if q:
        query = query.filter(
            or_(
                User.username.ilike(f'%{q}%'),
                User.email.ilike(f'%{q}%'),
                User.role.ilike(f'%{q}%')
            )
        )
    users_list = query.order_by(User.id).all()
    return render_template('users.html', users=users_list, search=q)

@app.route('/user/add', methods=['GET','POST'])
@login_required
@requires_permission('manage_users')
def add_user():
    if current_user.role not in ('admin','verwaltung'):
        flash('Zugriff verweigert', 'danger')
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        # Neuen User anlegen
        u = User(
            username     = form.username.data,
            email        = form.email.data,
            role         = form.role.data,
            group_number = form.group_number.data if form.role.data == 'kunde' else None
        )
        u.set_password(form.password.data)
        db.session.add(u)
        db.session.commit()

        flash('Benutzerkonto erstellt', 'success')
        return redirect(url_for('users'))

    return render_template('add_user.html', form=form)

@app.route('/contract/<int:loan_id>')
@login_required
def contract(loan_id):
    ln  = Loan.query.get_or_404(loan_id)
    bor = ln.borrower
    it  = ln.item

    # Wähle Template anhand der User-Rolle
    if bor.role == 'mitarbeiter':
        tpl = 'contract_employee.html'
    else:
        tpl = 'contract_customer.html'

    # HTML rendern und PDF erzeugen
    html    = render_template(tpl, loan=ln, borrower=bor, item=it)
    pdf_buf = BytesIO()
    HTML(string=html).write_pdf(target=pdf_buf)
    pdf_buf.seek(0)

    # PDF ausliefern
    return send_file(
        pdf_buf,
        download_name=f'Leihvertrag_{ln.id}.pdf',
        as_attachment=True
    )

@app.route('/meine_leihgaben')
@login_required
@requires_permission('view_own_loans')
def meine_leihgaben():
    if current_user.role != 'kunde':
        flash('Zugriff verweigert','danger')
        return redirect(url_for('dashboard'))
    # Borrower-Datensatz finden (nach E-Mail)
    bor = User.query.filter_by(email=current_user.email).first()
    if not bor:
        flash('Kein Entleiherprofil gefunden','warning')
        return redirect(url_for('dashboard'))
    # nur die eigenen Leihvorgänge
    loans = Loan.query.filter_by(borrower_id=bor.id).all()
    return render_template('meine_leihgaben.html', loans=loans)

@app.route('/tickets')
@login_required
@requires_permission('view_own_tickets')
def my_tickets():
    # alle Tickets des eingeloggten Users
    tickets = Ticket.query.filter_by(user_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template('tickets.html', tickets=tickets)

@app.route('/ticket/new', methods=['GET','POST'])
@login_required
def new_ticket():
    form = TicketForm()
    if form.validate_on_submit():
        t = Ticket(
            title      = form.title.data,
            description= form.description.data,
            user_id    = current_user.id
        )
        db.session.add(t)
        db.session.commit()
        flash('Dein Ticket wurde erstellt','success')
        return redirect(url_for('my_tickets'))
    return render_template('new_ticket.html', form=form)

@app.route('/ticket/<int:ticket_id>', methods=['GET','POST'])
@login_required
@requires_permission('answer_tickets')
def ticket_detail(ticket_id):
    t = Ticket.query.get_or_404(ticket_id)
    if current_user.role == 'borrower' and t.user_id != current_user.id:
        flash('Zugriff verweigert','danger')
        return redirect(url_for('my_tickets'))
    form = ResponseForm()
    if form.validate_on_submit():
        r = TicketResponse(
            ticket_id = t.id,
            user_id   = current_user.id,
            message   = form.message.data
        )
        db.session.add(r)
        db.session.commit()
        flash('Nachricht hinzugefügt','success')
        return redirect(url_for('ticket_detail', ticket_id=t.id))
    return render_template('ticket_detail.html', ticket=t, form=form)

@app.route('/admin/tickets', methods=['GET'])
@login_required
@requires_permission('view_admin_tickets')
def admin_tickets():
    if current_user.role not in ('admin','verwaltung'):
        abort(403)

    # 1) Alle Tickets laden
    tickets = Ticket.query.order_by(Ticket.status, Ticket.created_at.desc()).all()

    # 2) Für jedes Ticket eine eigene StatusForm erzeugen
    forms = {}
    for t in tickets:
        frm = StatusForm(prefix=f"f{t.id}")
        frm.status.data = t.status
        forms[t.id] = frm

    # 3) Tickets UND forms ans Template übergeben
    return render_template(
        'admin_tickets.html',
        tickets=tickets,
        forms=forms
    )


@app.route('/admin/ticket/<int:ticket_id>/status', methods=['POST'])
@login_required
@requires_permission('change_ticket_status')
def change_ticket_status(ticket_id):
    if current_user.role not in ('admin','verwaltung'):
        abort(403)
    new_status = request.form.get('status')
    t = Ticket.query.get_or_404(ticket_id)
    if new_status in ('open','in_progress','closed'):
        t.status = new_status
        db.session.commit()
        flash('Status aktualisiert','success')
    return redirect(url_for('admin_tickets'))

@app.route('/print_serial', methods=['POST'])
@login_required
def print_serial():
    data = request.get_json()
    serial = data.get('serial')
    if not serial:
        return jsonify({'success': False, 'error': 'Keine Seriennummer angegeben'}), 400
    zpl = f'^XA^FO50,50^BCN,100,Y,N,N^FD{serial}^FS^XZ'
    try:
        with socket.socket() as s:
            s.connect((app.config['PRINTER_IP'], app.config['PRINTER_PORT']))
            s.send(zpl.encode('utf-8'))
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f'Fehler beim Drucken des Barcodes: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/user/<int:user_id>/edit', methods=['GET','POST'])
@login_required
@requires_permission('manage_users')
def edit_user(user_id):
    u = User.query.get_or_404(user_id)
    form = EditUserForm(obj=u)
    if form.validate_on_submit():
        u.username     = form.username.data
        u.email        = form.email.data
        u.role         = form.role.data
        u.group_number = form.group_number.data if u.role == 'kunde' else None
        db.session.commit()
        flash('Benutzer aktualisiert','success')
        return redirect(url_for('users'))
    return render_template('edit_user.html', form=form, user=u)

@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
@requires_permission('manage_users')
def delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.username == current_user.username:
        flash('Du kannst dich nicht selbst löschen','warning')
    else:
        db.session.delete(u)
        db.session.commit()
        flash('Benutzer gelöscht','success')
    return redirect(url_for('users'))

@app.route('/admin/roles')
@login_required
@requires_permission('manage_roles')
def manage_roles():
    roles = Role.query.all()
    return render_template('admin_roles.html', roles=roles)

@app.route('/admin/role/<role_name>/edit', methods=['GET','POST'])
@login_required
@requires_permission('manage_roles')
def edit_role(role_name):
    role = Role.query.get_or_404(role_name)
    all_perms = Permission.query.order_by(Permission.name).all()
    if request.method == 'POST':
        selected = request.form.getlist('permissions')
        role.permissions = Permission.query.filter(
            Permission.name.in_(selected)
        ).all()
        db.session.commit()
        flash('Berechtigungen aktualisiert', 'success')
        return redirect(url_for('manage_roles'))
    return render_template(
        'edit_role.html',
        role=role,
        all_perms=all_perms
    )

@app.before_request
def load_settings():
    for s in Setting.query.all():
        # Typ-Casting je nach Schlüssel
        if s.key in ('MAIL_PORT','PRINTER_PORT'):
            app.config[s.key] = int(s.value)
        elif s.key == 'MAIL_USE_TLS':
            app.config[s.key] = s.value.lower() in ['true','1','yes']
        elif s.key == 'ADMINS':
            app.config['ADMINS'] = [e.strip() for e in s.value.split(';') if e.strip()]
        else:
            app.config[s.key] = s.value

@app.route('/admin/settings', methods=['GET','POST'])
@login_required
@requires_permission('manage_settings')
def admin_settings():
    form = SettingsForm()

    # Initialbefüllung aus DB
    if request.method == 'GET':
        vals = {s.key: s.value for s in Setting.query.all()}
        form.mail_server.data   = vals.get('MAIL_SERVER')
        form.mail_port.data     = int(vals.get('MAIL_PORT',0))
        form.mail_use_tls.data  = vals.get('MAIL_USE_TLS','false').lower() in ['true','1','yes']
        form.mail_username.data = vals.get('MAIL_USERNAME')
        form.admins.data        = vals.get('ADMINS')
        form.printer_ip.data    = vals.get('PRINTER_IP')
        form.printer_port.data  = int(vals.get('PRINTER_PORT',0))
        form.dell_client_id.data     = vals.get('DELL_CLIENT_ID')

    if form.validate_on_submit():
        updates = {
            'MAIL_SERVER':  form.mail_server.data,
            'MAIL_PORT':    form.mail_port.data,
            'MAIL_USE_TLS': str(form.mail_use_tls.data),
            'MAIL_USERNAME':form.mail_username.data,
            'MAIL_PASSWORD':form.mail_password.data,
            'ADMINS':       form.admins.data,
            'PRINTER_IP':   form.printer_ip.data,
            'PRINTER_PORT': form.printer_port.data,
            'DELL_CLIENT_ID':    form.dell_client_id.data,
            'DELL_CLIENT_SECRET':form.dell_client_secret.data
        }
        for k,v in updates.items():
            s = db.session.get(Setting, k)
            s.value = str(v)
        db.session.commit()
        flash('Einstellungen gespeichert','success')
        return redirect(url_for('admin_settings'))
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    log_path   = app.config.get('ERROR_LOG_PATH', os.path.join(app.instance_path,'error.log'))
    try:
        with open(log_path, encoding='utf-8') as f:
            errors = f.readlines()[-50:]
    except FileNotFoundError:
        errors = []

    return render_template(
      'admin_settings.html',
      form       = form,
      audits     = audit_logs,
      errors     = errors
    )

@app.route('/admin/setup')
@login_required
@requires_permission('manage_roles')
def admin_setup():
    """
    Führt einmalig oder on-demand die gesamte Setup-Routine aus.
    """
    setup()
    flash('Setup erfolgreich ausgeführt: Tabellen, Rollen, Permissions & Settings sind angelegt.', 'success')
    return redirect(url_for('dashboard'))

def setup():
    with app.app_context():
        # Tabellen anlegen
        db.create_all()

        # 1) Permissions anlegen
        perms = {
            'manage_users':        'Benutzerkonten verwalten',
            'manage_roles':        'Rollen & Berechtigungen verwalten',
            'manage_settings':     'System-Einstellungen verwalten',
            'view_dashboard':      'Dashboard anzeigen',
            'view_items':          'Gegenstände sehen',
            'view_loans':          'Ausleihen sehen',
            'view_tickets':        'Tickets sehen',
            'create_tickets':      'Tickets erstellen',
            'view_own_tickets':    'Eigene Tickets einsehen',
            'view_own_loans':      'Eigene Leihgaben einsehen',
            'answer_tickets':      'Tickets beantworten',
            'change_ticket_status':'Ticket-Status ändern',
            'view_admin_tickets':  'Admin-Tickets einsehen',
            'answer_admin_tickets':'Admin-Tickets beantworten',
            'manage_items':        'Items anlegen/bearbeiten'
        }
        for name, desc in perms.items():
            if not db.session.get(Permission, name):
                db.session.add(Permission(name=name, description=desc))

        # 2) Standard-Rollen anlegen
        for rn in ['admin', 'verwaltung', 'mitarbeiter', 'kunde']:
            if not db.session.get(Role, rn):
                db.session.add(Role(name=rn))

        db.session.commit()

        # 3) Default-Permissions zuweisen  ← Hier einsetzen
        admin_role = db.session.get(Role, 'admin')
        admin_role.permissions = Permission.query.all()

        verwaltung_role = db.session.get(Role, 'verwaltung')
        verwaltung_role.permissions = Permission.query.filter(
            Permission.name.in_([
                'view_dashboard',
                'view_items',
                'view_loans',
                'view_tickets',
                'view_borrowers',
                'answer_tickets',
                'change_ticket_status',
                'view_admin_tickets',
                'answer_admin_tickets',
                'manage_users',
                'manage_items'
            ])
        ).all()

        mitarbeiter_role = db.session.get(Role, 'mitarbeiter')
        mitarbeiter_role.permissions = Permission.query.filter(
            Permission.name.in_([
                'view_items',
                'view_loans',
                'create_tickets',
                'view_own_tickets',
                'view_own_loans'
            ])
        ).all()

        kunde_role = db.session.get(Role, 'kunde')
        kunde_role.permissions = Permission.query.filter(
            Permission.name.in_([
                'create_tickets',
                'view_own_tickets',
                'view_own_loans',
                'answer_tickets'
            ])
        ).all()

        db.session.commit()

        # 4) Default-Settings aus .env in DB anlegen
        defaults = {
            'MAIL_SERVER':   os.environ.get('MAIL_SERVER', ''),
            'MAIL_PORT':     os.environ.get('MAIL_PORT', '587'),
            'MAIL_USE_TLS':  os.environ.get('MAIL_USE_TLS', 'false'),
            'MAIL_USERNAME': os.environ.get('MAIL_USERNAME', ''),
            'MAIL_PASSWORD': os.environ.get('MAIL_PASSWORD', ''),
            'ADMINS':        os.environ.get('ADMIN_EMAIL', '').replace(',', ';'),
            'PRINTER_IP':    os.environ.get('PRINTER_IP', ''),
            'PRINTER_PORT':  os.environ.get('PRINTER_PORT', '9100'),
            'DELL_CLIENT_ID':     os.environ.get('DELL_CLIENT_ID',''),
            'DELL_CLIENT_SECRET': os.environ.get('DELL_CLIENT_SECRET',''),
        }
        for key, val in defaults.items():
            setting = db.session.get(Setting, key)
            if not setting:
                db.session.add(Setting(key=key, value=str(val)))

        db.session.commit()

        # 5) Standard-Admin anlegen (falls nicht vorhanden)
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    setup()
    app.run(host='0.0.0.0', port=5000)
