# -*- coding: utf-8 -*-
"""
Forms module for InventoryApp
All WTForms form definitions
"""

from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField, TextAreaField,
    SelectField, IntegerField, DecimalField, DateField,
    BooleanField, EmailField
)
from wtforms.validators import (
    DataRequired, Email, Length, EqualTo, ValidationError,
    Regexp, Optional
)
from flask import request
from datetime import date


class DummyForm(FlaskForm):
    borrower_name = StringField('Entleiher', validators=[DataRequired()])
    due_date      = DateField('Rückgabedatum', format='%Y-%m-%d', validators=[DataRequired()])
    submit        = SubmitField('Ausleihen')


class LoginForm(FlaskForm):
    username = StringField('Benutzername', validators=[DataRequired(), Length(min=4, max=64)])
    password = PasswordField('Passwort', validators=[DataRequired()], render_kw={'autocomplete': 'current-password'})
    submit   = SubmitField('Anmelden')


class ResetPasswordRequestForm(FlaskForm):
    email  = EmailField('E-Mail', validators=[DataRequired(), Email()])
    submit = SubmitField('Link zum Zurücksetzen senden')


class ResetPasswordForm(FlaskForm):
    password  = PasswordField('Neues Passwort', validators=[
        DataRequired(),
        Length(min=12, max=128, message='Passwort muss zwischen 12 und 128 Zeichen lang sein'),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])',
            message='Passwort muss Großbuchstaben, Kleinbuchstaben, Zahlen und Sonderzeichen (@$!%*?&) enthalten'
        )
    ])
    password2 = PasswordField('Passwort wiederholen',
                              validators=[DataRequired(), EqualTo('password')])
    submit    = SubmitField('Passwort zurücksetzen')


class InitialSetupForm(FlaskForm):
    username  = StringField('Admin-Benutzername', validators=[DataRequired(), Length(min=4, max=64)])
    email     = EmailField('Admin E-Mail', validators=[DataRequired(), Email()])
    password  = PasswordField('Passwort', validators=[
        DataRequired(),
        Length(min=12, max=128, message='Passwort muss zwischen 12 und 128 Zeichen lang sein'),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])',
            message='Passwort muss Großbuchstaben, Kleinbuchstaben, Zahlen und Sonderzeichen (@$!%*?&) enthalten'
        )
    ])
    password2 = PasswordField(
        'Passwort wiederholen',
        validators=[DataRequired(), EqualTo('password', message='Passwörter müssen übereinstimmen')]
    )
    submit = SubmitField('Admin-Account erstellen')


class BudgetForm(FlaskForm):
    """Form for creating and editing budget entries.

    This form matches the budget/add.html template and includes fields for
    budget name, category, amount, date range, description, and department.
    """
    name = StringField('Name', validators=[DataRequired(), Length(max=128)])
    category = SelectField('Kategorie', choices=[
        ('hardware', 'Hardware'),
        ('software', 'Software'),
        ('services', 'Dienstleistungen'),
        ('maintenance', 'Wartung'),
        ('other', 'Sonstiges')
    ], validators=[DataRequired()])
    amount = IntegerField('Budget-Betrag', validators=[DataRequired(message='Bitte geben Sie einen gültigen Betrag ein')])
    start_date = DateField('Startdatum', validators=[DataRequired(message='Startdatum ist erforderlich')])
    end_date = DateField('Enddatum', validators=[DataRequired(message='Enddatum ist erforderlich')])
    description = TextAreaField('Beschreibung')
    department = SelectField('Abteilung', choices=[
        ('it', 'IT'),
        ('sales', 'Vertrieb'),
        ('hr', 'Personal'),
        ('operations', 'Betrieb'),
        ('general', 'Allgemein')
    ], validators=[DataRequired()])
    submit = SubmitField('Budget erstellen')


class BudgetTransactionForm(FlaskForm):
    """Form for adding transactions to budget entries."""
    amount = DecimalField('Betrag', validators=[DataRequired()], places=2)
    transaction_type = SelectField('Transaktionstyp', choices=[
        ('expense', 'Ausgabe'),
        ('income', 'Einnahme'),
        ('depreciation', 'Abschreibung'),
        ('purchase', 'Einkauf')
    ], validators=[DataRequired()])
    transaction_date = DateField('Datum', validators=[DataRequired()], default=date.today)
    description = TextAreaField('Beschreibung', validators=[Length(max=500)])
    submit = SubmitField('Transaktion hinzufügen')


class TeamForm(FlaskForm):
    """Form for creating and editing teams.

    Provides fields for team management including basic information,
    contact details, member assignments, permissions, and status.
    """
    name = StringField('Teamname', validators=[DataRequired(message='Teamname ist erforderlich'), Length(max=128)])
    department = StringField('Abteilung', validators=[Length(max=128)])
    description = TextAreaField('Beschreibung', validators=[Length(max=500)])
    team_lead = StringField('Teamleiter', validators=[Length(max=128)])
    email = EmailField('E-Mail', validators=[Email(message='Ungültige E-Mail-Adresse')])
    phone = StringField('Telefon', validators=[Length(max=20)])

    # Note: members field would be a FieldList in a more complex implementation
    # For now, we'll handle members separately in the route
    members = None  # Placeholder - handled dynamically in template

    # Permissions
    can_view_all = BooleanField('Team kann alle Einträge sehen', default=False)
    can_edit_all = BooleanField('Team kann alle Einträge bearbeiten', default=False)
    can_delete_all = BooleanField('Team kann alle Einträge löschen', default=False)
    can_manage_team = BooleanField('Team kann Mitglieder verwalten', default=False)

    # Status
    is_active = BooleanField('Team ist aktiv', default=True)

    submit = SubmitField('Team erstellen')

    def validate_name(self, name):
        """Validate team name is unique."""
        # Import here to avoid circular import
        from app import Team
        team = Team.query.filter_by(name=name.data).first()
        if team:
            raise ValidationError('Ein Team mit diesem Namen existiert bereits.')


class RegistrationForm(FlaskForm):
    username  = StringField('Benutzername', validators=[DataRequired(), Length(min=4, max=64)])
    email     = EmailField('E-Mail', validators=[DataRequired(), Email()])
    password  = PasswordField('Passwort', validators=[
        DataRequired(),
        Length(min=12, max=128, message='Passwort muss zwischen 12 und 128 Zeichen lang sein'),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])',
            message='Passwort muss Großbuchstaben, Kleinbuchstaben, Zahlen und Sonderzeichen (@$!%*?&) enthalten'
        )
    ])
    password2 = PasswordField(
        'Passwort wiederholen',
        validators=[DataRequired(), EqualTo('password', message='Passwörter müssen übereinstimmen')]
    )
    role   = SelectField('Rolle', choices=[('admin','Admin'),('verwaltung','Verwaltung'), ('mitarbeiter', 'Mitarbeiter'), ('kunde', 'Kunde')], default='kunde')
    group_number = StringField('Gruppen-Nr. (nur für Kunden)', validators=[Length(max=32)])
    submit = SubmitField('Benutzer erstellen')

    def validate_username(self, username):
        from app import User
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Dieser Benutzername ist bereits vergeben.')

    def validate_email(self, email):
        from app import User
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Diese E-Mail-Adresse wird bereits verwendet.')


class ItemForm(FlaskForm):
    name     = StringField('Bezeichnung', validators=[DataRequired(), Length(max=128)])
    serial   = StringField('Seriennummer', validators=[DataRequired(), Length(max=64)])
    description = TextAreaField('Beschreibung', validators=[Length(max=500)])
    note      = TextAreaField('Notiz', validators=[Length(max=500)])

    # NEW: Use category_id instead of hardcoded choices
    category_id = SelectField('Kategorie', coerce=lambda x: int(x) if x and x != 'None' else None, validators=[])
    location_id = SelectField('Standort', coerce=lambda x: int(x) if x and x != 'None' else None, validators=[])
    parent_item_id = SelectField('Übergeordneter Gegenstand', coerce=lambda x: int(x) if x and x != 'None' else None, validators=[])

    # Budget & Value Tracking fields
    purchase_price = DecimalField('Einkaufspreis', places=2, validators=[Optional()])
    purchase_date = DateField('Kaufdatum', validators=[Optional()])
    deduct_from_budget = BooleanField('Von Budget abziehen', default=False)
    budget_id = SelectField('Budget', coerce=lambda x: int(x) if x and x != 'None' else None, validators=[Optional()])

    submit   = SubmitField('Speichern')

    def validate_serial(self, serial):
        # Skip validation if editing and serial hasn't changed
        from app import Item
        existing = Item.query.filter_by(serial=serial.data).first()
        if existing:
            # Check if this is the same item being edited
            item_id = request.view_args.get('item_id') if request.view_args else None
            if not item_id or existing.id != item_id:
                raise ValidationError('Diese Seriennummer existiert bereits.')


class CategoryForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=128)])
    description = TextAreaField('Beschreibung', validators=[Length(max=500)])
    icon = StringField('Icon (Bootstrap Icon)', validators=[Length(max=50)])
    color = StringField('Farbe (Hex)', validators=[Length(max=7)])
    submit = SubmitField('Speichern')


class LocationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=128)])
    parent_id = SelectField('Übergeordneter Standort', coerce=lambda x: int(x) if x and x != 'None' else None, validators=[])
    submit = SubmitField('Speichern')


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
    mail_password = PasswordField('SMTP Passwort', validators=[DataRequired()], render_kw={'autocomplete': 'current-password'})
    admins        = StringField('Admin E-Mails (mit „;" getrennt)')
    printer_ip    = StringField('Drucker-IP')
    printer_port  = IntegerField('Drucker-Port', validators=[DataRequired()])
    dell_client_id     = StringField('Dell API Client ID', validators=[DataRequired(), Length(max=128)])
    dell_client_secret = PasswordField('Dell API Client Secret', validators=[DataRequired(), Length(max=128)], render_kw={'autocomplete': 'off'})
    submit        = SubmitField('Speichern')
