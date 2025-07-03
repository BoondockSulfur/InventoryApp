# -*- coding: utf-8 -*-
import os
import uuid
import socket
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
    SelectField, DateField, EmailField
)
from wtforms.validators import (
    DataRequired, Length, Email, EqualTo, ValidationError
)
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from weasyprint import HTML
from dotenv import load_dotenv

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

# ─── App-Initialisierung ──────────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)
app.jinja_env.globals['date'] = date
csrf  = CSRFProtect(app)
db    = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'

# User loader für Flask-Login
@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

mail      = Mail(app)
scheduler = BackgroundScheduler()

# ─── Datenbank-Modelle ────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role          = db.Column(db.String(20), nullable=False, default='user')  # admin / user

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class Item(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(128), nullable=False)
    serial      = db.Column(db.String(64), unique=True, nullable=False)
    location    = db.Column(db.String(128))
    is_borrowed = db.Column(db.Boolean, default=False)
    defective   = db.Column(db.Boolean, default=False)

class Borrower(db.Model):
    id      = db.Column(db.Integer, primary_key=True)
    name    = db.Column(db.String(128), nullable=False)
    email   = db.Column(db.String(120), nullable=False)
    type    = db.Column(db.String(20), nullable=False)  # employee / participant
    loans   = db.relationship('Loan', backref='borrower', cascade='all, delete-orphan')

class Loan(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    item_id      = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    borrower_id  = db.Column(db.Integer, db.ForeignKey('borrower.id'), nullable=False)
    loan_date    = db.Column(db.Date, default=date.today, nullable=False)
    due_date     = db.Column(db.Date, nullable=False)
    return_date  = db.Column(db.Date)
    item         = db.relationship('Item', backref='loans')

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

# ─── Formulare ─────────────────────────────────────────────────────────────────
class DummyForm(FlaskForm):
    borrower_name = StringField('Entleiher', validators=[DataRequired()])
    due_date      = DateField('Rückgabedatum', format='%Y-%m-%d', validators=[DataRequired()])
    submit        = SubmitField('Ausleihen')

class LoginForm(FlaskForm):
    username = StringField('Benutzername', validators=[DataRequired(), Length(min=4, max=64)])
    password = PasswordField('Passwort', validators=[DataRequired()])
    submit   = SubmitField('Anmelden')

class RegistrationForm(FlaskForm):
    username  = StringField('Benutzername', validators=[DataRequired(), Length(min=4, max=64)])
    email     = EmailField('E-Mail', validators=[DataRequired(), Email()])
    password  = PasswordField('Passwort', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField(
        'Passwort wiederholen',
        validators=[DataRequired(), EqualTo('password', message='Passwörter müssen übereinstimmen')]
    )
    role   = SelectField('Rolle', choices=[('admin','Admin'),('user','User'), ('borrower', 'Entleiher')], default='borrower')
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

# ─── Hilfsfunktionen ──────────────────────────────────────────────────────────
def fetch_dell_license(serial):
    # Platzhalter für Dell-API
    return {'status': 'Aktiv', 'expiry': date(2025,12,31)}

def send_contract_email(loan):
    borrower = loan.borrower
    item     = loan.item
    tpl      = 'contract_employee.html' if borrower.type=='employee' else 'contract_participant.html'
    html     = render_template(tpl, loan=loan, borrower=borrower, item=item)
    pdf_buf  = BytesIO()
    HTML(string=html).write_pdf(target=pdf_buf)
    pdf_buf.seek(0)

    msg = Message(
        'Ihr Leihvertrag',
        sender=app.config['MAIL_USERNAME'],
        recipients=[borrower.email]
    )
    msg.body = 'Im Anhang finden Sie Ihren Leihvertrag.'
    msg.attach(f'Leihvertrag_{loan.id}.pdf','application/pdf',pdf_buf.read())
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
def items():
    q     = request.args.get('q','')
    query = Item.query
    if current_user.role == 'user':
        my_ids = [ln.item_id for ln in Loan.query.filter_by(borrower_id=current_user.id).all()]
        query  = query.filter(Item.id.in_(my_ids))
    if q:
        query = query.filter(Item.name.ilike(f'%{q}%'))
    lst = query.order_by(Item.is_borrowed.asc(), Item.name.asc()).all()
    return render_template('items.html', items=lst, search=q)

@app.route('/item/add', methods=['GET','POST'])
@login_required
def add_item():
    if current_user.role != 'admin':
        flash('Zugriff verweigert','danger')
        return redirect(url_for('items'))
    form = ItemForm()
    if form.validate_on_submit():
        itm = Item(name=form.name.data, serial=form.serial.data, location=form.location.data)
        db.session.add(itm)
        db.session.commit()
        flash('Gegenstand hinzugefügt','success')
        return redirect(url_for('items'))
    return render_template('add_item.html', form=form)

@app.route('/item/<int:item_id>')
@login_required
def item_detail(item_id):
    itm         = Item.query.get_or_404(item_id)
    lic         = fetch_dell_license(itm.serial)
    act_loan    = Loan.query.filter_by(item_id=itm.id, return_date=None).first()
    return_form = ReturnForm()
    today       = date.today()
    return render_template(
        'item_detail.html',
        item=itm, loan=act_loan, license=lic,
        return_form=return_form, today=today
    )

@app.route('/item/<int:item_id>/loan', methods=['GET','POST'])
@login_required
def loan_item(item_id):
    itm       = Item.query.get_or_404(item_id)
    borrowers = Borrower.query.all()
    form      = DummyForm()
    if form.validate_on_submit():
        bor = Borrower.query.filter_by(name=form.borrower_name.data.strip()).first()
        if not bor:
            flash('Entleiher nicht gefunden','danger')
            return redirect(url_for('loan_item', item_id=item_id))
        if form.due_date.data < date.today():
            flash('Rückgabedatum in der Vergangenheit','warning')
            return redirect(url_for('loan_item', item_id=item_id))
        ln = Loan(item_id=itm.id, borrower_id=bor.id, due_date=form.due_date.data)
        itm.is_borrowed = True
        db.session.add(ln)
        db.session.commit()
        flash('Leihvorgang erstellt','success')
        send_contract_email(ln)
        return redirect(url_for('item_detail', item_id=item_id))
    return render_template('loan_form.html', item=itm, borrowers=borrowers, form=form)

@app.route('/item/<int:item_id>/return', methods=['POST'])
@login_required
def return_item(item_id):
    form = ReturnForm()
    if not form.validate_on_submit():
        flash('Ungültige Anfrage','danger')
        return redirect(url_for('item_detail', item_id=item_id))
    if current_user.role != 'admin':
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
    if current_user.role != 'admin':
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
    if current_user.role != 'admin':
        abort(403)
    itm = Item.query.get_or_404(item_id)
    itm.defective = False
    itm.is_borrowed = False  # wieder verfügbar
    db.session.commit()
    flash('Gegenstand als repariert markiert','success')
    return redirect(url_for('item_detail', item_id=item_id))


@app.route('/borrowers')
@login_required
def borrowers():
    b_list = Borrower.query.all()
    return render_template('borrowers.html', borrowers=b_list)

@app.route('/borrower/add', methods=['GET','POST'])
@login_required
def add_borrower():
    if current_user.role != 'admin':
        flash('Zugriff verweigert','danger')
        return redirect(url_for('borrowers'))
    form = BorrowerForm()
    if form.validate_on_submit():
        bor = Borrower(name=form.name.data, email=form.email.data, type=form.type.data)
        db.session.add(bor)
        db.session.commit()
        flash('Entleiher hinzugefügt','success')
        return redirect(url_for('borrowers'))
    return render_template('add_borrower.html', form=form)

@app.route('/loans/active')
@login_required
def active_loans():
    loans = Loan.query.filter_by(return_date=None).all()
    today = date.today()
    return render_template('active_loans.html', loans=loans, today=today)

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Zugriff verweigert','danger')
        return redirect(url_for('dashboard'))
    usr_list = User.query.all()
    return render_template('users.html', users=usr_list)

@app.route('/user/add', methods=['GET','POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Zugriff verweigert','danger')
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # Neuen User anlegen
        u = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data
        )
        u.set_password(form.password.data)
        db.session.add(u)
        db.session.commit()

        # Falls Entleiher-Rolle, auch Borrower anlegen
        if form.role.data == 'borrower':
            b = Borrower(
                name=form.username.data,
                email=form.email.data,
                type='participant'
            )
            db.session.add(b)
            db.session.commit()

        flash('Benutzerkonto erstellt','success')
        return redirect(url_for('users'))
    return render_template('add_user.html', form=form)

@app.route('/contract/<int:loan_id>')
@login_required
def contract(loan_id):
    ln = Loan.query.get_or_404(loan_id)
    bor=ln.borrower
    it =ln.item
    tpl = 'contract_employee.html' if bor.type=='employee' else 'contract_participant.html'
    html    = render_template(tpl, loan=ln, borrower=bor, item=it)
    pdf_buf = BytesIO()
    HTML(string=html).write_pdf(target=pdf_buf)
    pdf_buf.seek(0)
    return send_file(pdf_buf, download_name=f'Leihvertrag_{ln.id}.pdf', as_attachment=True)

def setup():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            a = User(username='admin', email='admin@example.com', role='admin')
            a.set_password('admin')
            db.session.add(a)
            db.session.commit()
            print('Default admin created: admin/admin')

@app.route('/meine_leihgaben')
@login_required
def meine_leihgaben():
    if current_user.role != 'borrower':
        flash('Zugriff verweigert','danger')
        return redirect(url_for('dashboard'))
    # Borrower-Datensatz finden (nach E-Mail)
    bor = Borrower.query.filter_by(email=current_user.email).first()
    if not bor:
        flash('Kein Entleiherprofil gefunden','warning')
        return redirect(url_for('dashboard'))
    # nur die eigenen Leihvorgänge
    loans = Loan.query.filter_by(borrower_id=bor.id).all()
    return render_template('meine_leihgaben.html', loans=loans)

@app.route('/tickets')
@login_required
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
def admin_tickets():
    if current_user.role != 'admin':
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
def change_ticket_status(ticket_id):
    if current_user.role != 'admin':
        abort(403)
    new_status = request.form.get('status')
    t = Ticket.query.get_or_404(ticket_id)
    if new_status in ('open','in_progress','closed'):
        t.status = new_status
        db.session.commit()
        flash('Status aktualisiert','success')
    return redirect(url_for('admin_tickets'))

if __name__ == '__main__':
    setup()
    app.run(host='0.0.0.0', port=5000)
