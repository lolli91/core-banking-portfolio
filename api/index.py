from io import BytesIO
from flask import Flask, jsonify, render_template, request, flash, redirect, session, url_for
from flask_wtf import FlaskForm
from flask_migrate import Migrate
import requests
from wtforms import BooleanField, StringField, TextAreaField, SubmitField, DateTimeLocalField, PasswordField, ValidationError
from wtforms.validators import DataRequired, Email, Length, Optional
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.file import FileField, FileAllowed, FileRequired
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_recaptcha import ReCaptcha
from markupsafe import Markup
from functools import wraps
from datetime import datetime, timedelta, timezone
import os
import smtplib
import uuid
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

# =========================
# APP CONFIGURATION
# =========================

app = Flask(__name__,
            template_folder='../templates',
            static_folder='../static')

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") or os.urandom(32).hex()
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'rago_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv("FLASK_ENV", "development") == "production"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=14)
app.config['RECAPTCHA_PUBLIC_KEY']  = "6Lew7nksAAAAAG16wmOBYH_tq7_A1KfRJuyCpD2Y"
app.config['RECAPTCHA_PRIVATE_KEY'] = "6Lew7nksAAAAAIShY4akF51fQZHHSA3Jz9ur2Taj"


# Local upload folder (persistent on PythonAnywhere)
UPLOAD_FOLDER = os.path.join(app.static_folder, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
migrate = Migrate(app, db)
recaptcha = ReCaptcha(app)


from markupsafe import Markup
import flask_recaptcha
flask_recaptcha.Markup = Markup

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

# Email config (Gmail SMTP works on free tier)
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", 587))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS", "True") == "True"
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")

    
# =========================
# MODELS
# =========================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(150), nullable=True)          # ← NEW
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="admin")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    profile_picture = db.Column(db.String(255), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)


class OTPCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)   # ← Changed to nullable=True
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    used = db.Column(db.Boolean, default=False)


class ResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class POCRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reference_id = db.Column(db.String(20), unique=True, nullable=False, index=True)  # ← NEW
    organization = db.Column(db.String(150), nullable=False)
    contact_person = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(30))
    description = db.Column(db.Text, nullable=False)
    request_type = db.Column(db.String(20), nullable=False)
    attachment = db.Column(db.String(255))
    status = db.Column(db.String(30), default="Pending")
    scheduled_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class RequestVerificationToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    form_data = db.Column(db.JSON, nullable=False)  # store serialized form data
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    used = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<VerificationToken {self.token} for {self.email}>"
    
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# =========================
# FORMS
# =========================
class ProfilePictureForm(FlaskForm):
    profile_picture = FileField('Profile Picture', 
                                validators=[
                                    FileRequired(),
                                    FileAllowed(['jpg', 'jpeg', 'png'], 'Only JPG/PNG allowed!')
                                ])
    submit = SubmitField('Upload')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    company = StringField('Company Name (Optional)', validators=[Length(max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[Length(max=20)])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=2, max=5000)])
    submit = SubmitField('Send Message')


class POCRequestForm(FlaskForm):
    organization = StringField('Organization', validators=[DataRequired()])
    contact_person = StringField('Contact Person', validators=[DataRequired()])
    email = StringField('Official Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone')
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Submit Request')


class AdminLoginForm(FlaskForm):
    username = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class Verify2FAForm(FlaskForm):
    code = StringField('Verification Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')

    def validate_confirm_password(self, field):
        if field.data != self.password.data:
            raise ValidationError('Passwords do not match.')


class ScheduleForm(FlaskForm):
    scheduled_date = DateTimeLocalField(
        'Schedule Date & Time',
        format='%Y-%m-%dT%H:%M',
        validators=[DataRequired()]
    )
    attachment = FileField(
        'Attach Supporting Document (optional)',
        validators=[
            FileAllowed(
                ['pdf', 'xlsx', 'xls', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'gif'],
                'Allowed formats: PDF, Excel, Word, Images'
            )
        ]
    )
    submit = SubmitField("Schedule & Notify")

from wtforms.validators import Optional

class PublicDemoForm(FlaskForm):
    organization = StringField('Organization / Institution', validators=[DataRequired()])
    contact_person = StringField('Contact Person', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number')

    request_type = StringField('Request Type', validators=[DataRequired()])

    scheduled_date = DateTimeLocalField(
        'Preferred Date & Time',
        format='%Y-%m-%dT%H:%M',
        validators=[Optional()]   # ← This allows empty submission without parsing error
    )

    description = TextAreaField('Additional Details / Questions', validators=[DataRequired()])
    attachment = FileField(
        'Supporting Document (for POC only)',
        validators=[FileAllowed(['pdf', 'doc', 'xlsx', 'xls', 'docx', 'zip'], 'Only PDF, Word, Excel or ZIP allowed')]
    )
    submit = SubmitField('Submit Request')

    def validate_scheduled_date(self, field):
        # Only require it for POC and Demo
        if self.request_type.data in ('POC', 'Demo'):
            if not field.data:
                raise ValidationError('This field is required for POC and Demo requests.')
        # Enquiry → allow None / empty

class ReplyClientForm(FlaskForm):
    subject = StringField('Subject', validators=[DataRequired(), Length(max=200)])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=2, max=5000)])
    attachment = FileField(
        'Attach File (optional)',
        validators=[FileAllowed(['pdf', 'doc', 'docx', 'xlsx', 'xls', 'jpg', 'jpeg', 'png', 'zip'], 
                                'Allowed formats: PDF, Word, Excel, Images, ZIP')]
    )
    cc_email = StringField('CC (optional – comma separated)', 
                           validators=[Optional()])
    submit = SubmitField('Send Reply')

class ClientReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('poc_request.id'), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    attachment = db.Column(db.String(255), nullable=True)
    sent_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    sent_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # New field for CC logging
    cc_recipients = db.Column(db.String(500), nullable=True)  # comma-separated emails

    request = db.relationship('POCRequest', backref=db.backref('replies', lazy=True, cascade="all, delete-orphan"))
    sent_by = db.relationship('User', backref=db.backref('sent_replies', lazy=True))

    def __repr__(self):
        return f"<Reply {self.id} to {self.request.reference_id}>"

class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    full_name = StringField('Full Name', validators=[Length(max=150)])  # ← NEW
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    role = StringField('Role', validators=[DataRequired()], default="admin")
    submit = SubmitField('Create User')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data.strip()).first():
            raise ValidationError('Username already exists.')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.strip().lower()).first():
            raise ValidationError('Email already in use.')

class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    full_name = StringField('Full Name', validators=[Length(max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = StringField('Role', validators=[DataRequired()])
    password = PasswordField('New Password (leave blank to keep current)', validators=[Optional(), Length(min=8)])
    submit = SubmitField('Update User')

    def __init__(self, user_id=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_id = user_id

    def validate_username(self, field):
        existing = User.query.filter_by(username=field.data.strip()).first()
        if existing and existing.id != self.user_id:
            raise ValidationError('Username already exists.')

    def validate_email(self, field):
        existing = User.query.filter_by(email=field.data.strip().lower()).first()
        if existing and existing.id != self.user_id:
            raise ValidationError('Email already in use.')

# Forms (add/update these in your forms section)
class FollowUpLookupForm(FlaskForm):
    reference_id = StringField('Ticket ID (e.g. REF-0012345678)', 
                              validators=[DataRequired(), Length(min=10, max=20)])
    submit_lookup = SubmitField('Fetch My Requests')

class OTPVerifyForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit_otp = SubmitField('Verify & Fetch Requests')

class FollowUpMessageForm(FlaskForm):
    message = TextAreaField('Your Message / Question', 
                           validators=[DataRequired(), Length(min=2, max=5000)])
    attachment = FileField('Attach File (optional)', 
                          validators=[FileAllowed(['pdf','doc','docx','xlsx','xls','jpg','jpeg','png','zip'])])
    submit_message = SubmitField('Send Follow-up Message')
        
# =========================
# DECORATORS
# =========================
def role_required(*required_roles):
    """Decorator: restrict access to users with one of the specified roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for('admin_login'))

            if current_user.role not in required_roles:
                flash(f"Access denied. This page requires one of these roles: {', '.join(required_roles)}.", "danger")
                return redirect(url_for('dashboard'))  # or a 403 page

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def generate_reference_id():
    """Generate unique REF-00XXXXXXXX format (8 random digits)"""
    while True:
        # Generate 8 random digits
        digits = ''.join(random.choices(string.digits, k=8))
        ref_id = f"REF-00{digits}"
        
        # Check if already exists
        if not POCRequest.query.filter_by(reference_id=ref_id).first():
            return ref_id
        
def save_unique_attachment(file, organization):
    """
    Save file with organization prefix + handle duplicates by adding (1), (2), ...
    Returns the final stored filename (without path).
    """
    if not file:
        return None

    # Sanitize organization name for filename
    org_clean = secure_filename(organization.lower().replace(" ", "-").replace("/", "-"))
    original_name = secure_filename(file.filename)
    
    # Combine: organization-original.ext
    base_name, ext = os.path.splitext(original_name)
    desired_name = f"{org_clean}-{base_name}{ext}" if org_clean else original_name
    
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], desired_name)
    counter = 1
    
    # Check for conflicts and append (1), (2), ...
    while os.path.exists(upload_path):
        new_name = f"{org_clean}-{base_name}({counter}){ext}" if org_clean else f"{base_name}({counter}){ext}"
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], new_name)
        counter += 1
    
    file.save(upload_path)
    # Return only the filename (what we store in DB)
    return os.path.basename(upload_path)

# =========================
# EMAIL UTILITIES
# =========================
def send_email(to_email, subject, plain_body, html_body=None, attachment_path=None, extra_attachment=None, cc=None):
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        print("Email credentials not configured.")
        return

    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Add CC if provided
        if cc and isinstance(cc, list) and cc:
            msg['Cc'] = ", ".join(cc)

        msg.attach(MIMEText(plain_body, 'plain'))
        if html_body:
            msg.attach(MIMEText(html_body, 'html'))

        # Main attachment
        if attachment_path and os.path.exists(attachment_path):
            part = MIMEBase('application', "octet-stream")
            with open(attachment_path, 'rb') as f:
                part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(attachment_path)}"')
            msg.attach(part)

        # Extra attachment (if any)
        if extra_attachment and os.path.exists(extra_attachment):
            part2 = MIMEBase('application', "octet-stream")
            with open(extra_attachment, 'rb') as f:
                part2.set_payload(f.read())
            encoders.encode_base64(part2)
            part2.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(extra_attachment)}"')
            msg.attach(part2)

        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        if app.config['MAIL_USE_TLS']:
            server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.sendmail(
            app.config['MAIL_USERNAME'], 
            [to_email] + (cc or []),  # send to To + CC recipients
            msg.as_string()
        )
        server.quit()
        print(f"[EMAIL SENT] to {to_email} - Subject: {subject}")
        if cc:
            print(f"  CC: {', '.join(cc)}")
    except Exception as e:
        print("Email Error:", str(e))

@app.route('/api/pending-count')
@login_required
@role_required('superadmin', 'admin', 'team', 'viewer')
def pending_count():
    pending = POCRequest.query.filter_by(status="Pending").count()
    pending_requests = POCRequest.query.filter_by(status="Pending").order_by(POCRequest.created_at.desc()).limit(8).all()
    
    return jsonify({
        "pending_count": pending,
        "pending_requests": [{
            "id": r.id,
            "organization": r.organization,
            "request_type": r.request_type,
            "contact_person": r.contact_person,
            "created_at": r.created_at.strftime("%d %b %Y %H:%M")
        } for r in pending_requests]
    })

@app.route('/upload_profile_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    form = ProfilePictureForm()
    if form.validate_on_submit():
        file = form.profile_picture.data
        if file:
            filename = secure_filename(f"{current_user.id}_{file.filename}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Update user profile picture
            current_user.profile_picture = filename
            db.session.commit()
            
            flash("Profile picture updated successfully!", "success")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {field}: {error}", "danger")
    
    return redirect(url_for('dashboard'))

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')

    def validate_current_password(self, field):
        if not current_user.check_password(field.data):
            raise ValidationError('Current password is incorrect.')

    def validate_confirm_password(self, field):
        if field.data != self.new_password.data:
            raise ValidationError('Passwords do not match.')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_user.set_password(form.new_password.data)
        db.session.commit()
        flash("Password changed successfully!", "success")
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html', form=form)


@app.route('/reply/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('superadmin', 'admin', 'team')
def reply_client(id):
    req = POCRequest.query.get_or_404(id)
    form = ReplyClientForm()

    if form.validate_on_submit():
        reply_subject = f"Re: {form.subject.data}"

        # Build HTML email body (unchanged)
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Reply from Rago Global Solutions</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
                .container {{ max-width: 600px; margin: 30px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
                .header {{ background: #001f3f; color: white; padding: 40px 30px; text-align: center; }}
                .header h1 {{ margin: 0; font-size: 28px; }}
                .content {{ padding: 40px 30px; color: #333; line-height: 1.7; }}
                .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }}
                .btn {{ display: inline-block; background: #007BFF; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
                .highlight {{ color: #001f3f; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Message from Rago Global Solutions</h1>
                </div>
                <div class="content">
                    <p>Dear <strong>{req.contact_person}</strong>,</p>
                    <p style="white-space: pre-wrap;">{form.message.data}</p>
                    <p style="margin-top: 30px; text-align: center;">
                        <a href="https://ragoglobal.pythonanywhere.com" class="btn">Visit Our Website</a>
                    </p>
                    <p>Reference ID for this conversation: <strong class="highlight">{req.reference_id}</strong><br>
                    Please include this reference in any future replies for faster assistance.</p>
                    <p>Best regards,<br>
                    <strong>Rago Global Solutions Team</strong><br>
                    <a href="mailto:helpdesk.ragosa.tech@gmail.com">helpdesk.ragosa.tech@gmail.com</a><br>
                    +234 813 887 9938</p>
                </div>
                <div class="footer">
                    © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
                </div>
            </div>
        </body>
        </html>
        """

        plain_body = f"""Dear {req.contact_person},

{form.message.data}

Ticket ID: {req.reference_id}
Please quote this reference in any follow-up messages.

Best regards,
Rago Global Solutions Team
helpdesk.ragosa.tech@gmail.com
+234 813 887 9938
"""

        # Handle attachment
        reply_attachment_path = None
        attachment_filename = None
        if form.attachment.data:
            filename = secure_filename(form.attachment.data.filename)
            safe_name = f"reply-{req.reference_id}-{filename}"
            reply_attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
            form.attachment.data.save(reply_attachment_path)
            attachment_filename = safe_name

        # Parse CC emails (comma-separated)
        cc_list = []
        cc_string_for_db = None
        if form.cc_email.data and form.cc_email.data.strip():
            # Split by comma, strip whitespace, filter valid-looking emails
            raw_emails = [email.strip() for email in form.cc_email.data.split(',') if email.strip()]
            # Basic validation: must contain @ and a dot after it
            cc_list = [email for email in raw_emails if '@' in email and '.' in email.split('@')[-1]]
            if cc_list:
                cc_string_for_db = ', '.join(cc_list)

        # Send email (with CC if any)
        send_email(
            to_email=req.email,
            subject=reply_subject,
            plain_body=plain_body,
            html_body=html_body,
            attachment_path=reply_attachment_path,
            cc=cc_list if cc_list else None
        )

        # Save reply with CC logging
        new_reply = ClientReply(
            request_id=req.id,
            subject=reply_subject,
            message=form.message.data,
            attachment=attachment_filename,
            sent_by_id=current_user.id,
            cc_recipients=cc_string_for_db  # saved as comma-separated string
        )
        db.session.add(new_reply)
        db.session.commit()

        flash(f"Reply sent successfully to {req.email} (Ticket ID: {req.reference_id}).", "success")
        return redirect(url_for('view_conversation', request_id=req.id))

    return render_template("reply_client.html", form=form, request=req)

@app.route('/conversation/<int:request_id>')
@login_required
@role_required('superadmin', 'admin', 'team')
def view_conversation(request_id):
    req = POCRequest.query.get_or_404(request_id)
    
    # Get replies, newest first
    replies = ClientReply.query.filter_by(request_id=req.id)\
                              .order_by(ClientReply.sent_at.desc())\
                              .all()
    
    return render_template(
        'conversation.html',
        request=req,
        replies=replies
    )

def generate_ics_file(request_obj):
    os.makedirs(app.static_folder, exist_ok=True)
    
    type_prefix = request_obj.request_type.lower()
    filename = f"{type_prefix}_schedule_{uuid.uuid4()}.ics"
    filepath = os.path.join(app.static_folder, filename)

    lagos_tz = timezone(timedelta(hours=1))  # WAT = UTC+1, no DST

    # If scheduled_date is naive → assume it's in Lagos time
    if request_obj.scheduled_date.tzinfo is None:
        start_local = request_obj.scheduled_date.replace(tzinfo=lagos_tz)
    else:
        start_local = request_obj.scheduled_date

    # Convert to UTC for ICS
    start_utc = start_local.astimezone(timezone.utc)
    end_utc   = start_utc

    event_title = f"Core Banking {request_obj.request_type} - Rago Global Solutions"
    
    event_desc = (
        f"{request_obj.request_type} Session with {request_obj.organization}\n"
        f"Contact: {request_obj.contact_person} ({request_obj.email})\n"
        f"Phone: {request_obj.phone or 'Not provided'}\n\n"
        "Please be prepared with any questions or requirements.\n"
        "Join via the link or details that will be shared closer to the time."
    )

    escaped_desc = event_desc.replace("\n", "\\n")

    content = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Rago Global Solutions//EN
BEGIN:VEVENT
UID:{uuid.uuid4()}
SUMMARY:{event_title}
DTSTART:{start_utc.strftime("%Y%m%dT%H%M%SZ")}
DTEND:{end_utc.strftime("%Y%m%dT%H%M%SZ")}
DESCRIPTION:{escaped_desc}
LOCATION:Online / Virtual Meeting
END:VEVENT
END:VCALENDAR"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

    return filepath


# =========================
# ROUTES
# =========================
@app.route("/", methods=["GET", "POST"])
def home():
    form = ContactForm()
    poc_form = POCRequestForm()

    if form.submit.data and form.validate_on_submit():
        flash("Message sent successfully!", "success")
        return redirect(url_for("home") + "#contact")

    if poc_form.submit.data and poc_form.validate_on_submit():
        new_request = POCRequest(
            organization=poc_form.organization.data,
            contact_person=poc_form.contact_person.data,
            email=poc_form.email.data,
            phone=poc_form.phone.data,
            description=poc_form.description.data
        )
        db.session.add(new_request)
        db.session.commit()

        send_email(
            poc_form.email.data,
            "POC Request Received – Rago Global Solutions",
            f"Dear {poc_form.contact_person.data},\n\nYour POC request has been received.\nOur team will review and contact you soon.\n\nBest regards,\nRago Global Solutions"
        )

        flash("POC Request submitted successfully!", "success")
        return redirect(url_for("home") + "#poc")

    return render_template("index.html", form=form, poc_form=poc_form)


@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
  
    form = AdminLoginForm()
    if form.validate_on_submit():
        # Search for user by username OR email (email is case-insensitive)
        user = User.query.filter(
            (User.username == form.username.data.strip()) |
            (User.email == form.username.data.strip().lower())
        ).first()

        if not user or not user.check_password(form.password.data):
            flash("Invalid username/email or password.", "danger")
            return render_template("admin_login.html", form=form)
       
        # Generate OTP
        code = ''.join(random.choices(string.digits, k=6))
        otp = OTPCode(
            user_id=user.id,
            code=code,
            created_at=datetime.now(timezone.utc),
            used=False
        )
        db.session.add(otp)
        db.session.commit()

        # Send OTP email (your existing beautiful HTML email code)
        otp_subject = "Rago Admin - Your Login Verification Code"
        otp_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>{otp_subject}</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
                .container {{ max-width: 620px; margin: 40px auto; background: white; border-radius: 20px; overflow: hidden; box-shadow: 0 12px 50px rgba(0,0,0,0.15); }}
                .header {{ background: linear-gradient(135deg, #001f3f, #003366); color: white; padding: 70px 50px 60px; text-align: center; }}
                .header h1 {{ margin: 0; font-size: 30px; letter-spacing: 1px; }}
                .content {{ padding: 50px 50px 60px; color: #333; line-height: 1.8; }}
                .otp-box {{
                    font-size: 32px; font-weight: 800; letter-spacing: 16px; color: #60a5fa;
                    background: #f0f7ff; padding: 28px; text-align: center; border-radius: 16px;
                    margin: 40px 0; box-shadow: inset 0 4px 15px rgba(96,165,250,0.15);
                }}
                .btn {{
                    display: inline-block; background: linear-gradient(90deg, #007BFF, #0056b3);
                    color: white !important; padding: 16px 60px; text-decoration: none;
                    border-radius: 50px; font-size: 16px; font-weight: 600; margin: 35px 0;
                    box-shadow: 0 8px 25px rgba(0,123,255,0.35); transition: all 0.3s;
                }}
                .btn:hover {{ transform: translateY(-3px); box-shadow: 0 12px 35px rgba(0,123,255,0.5); }}
                .footer {{ background: #001f3f; color: #cbd5e1; padding: 35px; text-align: center; font-size: 14px; }}
                .highlight {{ color: #93c5fd; font-weight: 600; }}
                
                @media only screen and (max-width: 600px) {{
                    body, p, div {{ font-size: 15px !important; line-height: 1.6 !important; }}
                    h1 {{ font-size: 24px !important; }}
                    .otp-box {{
                        font-size: 16px !important;
                        letter-spacing: 5px !important;
                        padding: 20px !important;
                        margin: 30px 0 !important;
                    }}
                    .btn {{ font-size: 16px !important; padding: 12px 40px !important; }}
                    .content {{ padding: 30px 20px !important; }}
                    .header {{ padding: 50px 20px 40px !important; }}
                    .footer {{ font-size: 13px !important; padding: 25px !important; }}
                }}
                @media only screen and (max-width: 400px) {{
                    .otp-box {{ font-size: 16px !important; letter-spacing: 4px !important; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Secure Login Verification</h1>
                </div>
                <div class="content">
                    <p>Hello <strong>{user.full_name}</strong>,</p>
                    <p>We received a login request to your Rago Admin account. Use the code below to continue:</p>
                    <div class="otp-box">{code}</div>
                    <p>This code is valid for <strong>10 minutes</strong>. Do not share it with anyone.</p>
                    <p style="text-align: center;">
                        <a href="{url_for('verify_2fa', _external=True)}" class="btn">Enter Verification Code</a>
                    </p>
                    <p>If you did not initiate this login, please <span class="highlight">secure your account immediately</span> and contact support.</p>
                    <p>Best regards,<br>
                    <strong>Rago Global Admin Security Team</strong><br>
                    <a href="mailto:helpdesk.ragosa.tech@gmail.com" style="color:#93c5fd;">helpdesk.ragosa.tech@gmail.com</a></p>
                </div>
                <div class="footer">
                    © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
                </div>
            </div>
        </body>
        </html>
        """
        send_email(
            user.email,
            otp_subject,
            plain_body=f"Your one-time login code: {code}\n\nThis code expires in 10 minutes.\nDo not share it.",
            html_body=otp_html
        )

        # Store user ID and remember choice
        session['pending_user_id'] = user.id
        session['remember'] = form.remember.data
        flash("A 6-digit verification code has been sent to your email.", "info")
        return redirect(url_for('verify_2fa'))

    return render_template("admin_login.html", form=form)


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_user_id' not in session:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for('admin_login'))

    # Use modern Session.get() instead of legacy Query.get()
    user = db.session.get(User, session['pending_user_id'])
    if not user:
        session.pop('pending_user_id', None)
        flash("User not found. Please log in again.", "danger")
        return redirect(url_for('admin_login'))

    # Get most recent unused OTP
    otp = OTPCode.query.filter_by(user_id=user.id, used=False)\
                       .order_by(OTPCode.created_at.desc()).first()

    if not otp:
        flash("No active verification code found. Please log in again.", "danger")
        session.pop('pending_user_id', None)
        return redirect(url_for('admin_login'))

    # ── FIX TIMEZONE MISMATCH ────────────────────────────────────────
    created_at = otp.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)  # assume old OTPs are UTC

    expires_at = created_at + timedelta(minutes=10)
    now_utc = datetime.now(timezone.utc)

    time_left_seconds = max(0, int((expires_at - now_utc).total_seconds()))
    # ─────────────────────────────────────────────────────────────────

    form = Verify2FAForm()
    if form.validate_on_submit():
        entered_code = form.code.data.strip()
        if otp.code == entered_code:
            if now_utc < expires_at:
                otp.used = True
                db.session.commit()
                remember = session.pop('remember', False)
                login_user(user, remember=remember)
                session.pop('pending_user_id', None)
                flash("Login successful.", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("This code has expired. Please log in again.", "danger")
        else:
            flash("Incorrect verification code.", "danger")

    return render_template(
        "verify_2fa.html",
        form=form,
        email=user.email,
        time_left_seconds=time_left_seconds
    )


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = ForgotPasswordForm()
    
    if form.validate_on_submit() and recaptcha.verify():
        user = User.query.filter_by(email=form.email.data.strip()).first()
        if user:
            token = str(uuid.uuid4())
            reset = ResetToken(user_id=user.id, token=token)
            db.session.add(reset)
            db.session.commit()
            
            reset_url = url_for('reset_password', token=token, _external=True)
            send_email(
                user.email,
                "Rago Admin - Password Reset Request",
                f"Click here to reset your password:\n{reset_url}\n\nThis link expires in 60 minutes.\nIf you did not request this, ignore this email."
            )
        flash("If an account exists with that email, a reset link has been sent.", "info")
        return redirect(url_for('admin_login'))
    
    elif request.method == 'POST':
        flash("Please complete the CAPTCHA verification.", "danger")
    
    return render_template("forgot_password.html", form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset = ResetToken.query.filter_by(token=token).first()
    
    if not reset:
        flash("Invalid reset link.", "danger")
        return redirect(url_for('forgot_password'))
    
    # Make created_at aware if it is naive (handles old records)
    created_at = reset.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    
    # Now safe to compare
    if (datetime.now(timezone.utc) - created_at) > timedelta(hours=1):
        flash("This reset link has expired.", "danger")
        return redirect(url_for('forgot_password'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = db.session.get(User, reset.user_id)  # better than query.get()
        if user:
            user.set_password(form.password.data)
            db.session.delete(reset)
            db.session.commit()
            flash("Password reset successful. Please log in.", "success")
            return redirect(url_for('admin_login'))
        else:
            flash("User not found.", "danger")
    
    # Calculate remaining time (also handle naive case)
    expires_at = created_at + timedelta(hours=1)
    expires_in = max(0, int((expires_at - datetime.now(timezone.utc)).total_seconds() // 60))
    
    return render_template(
        "reset_password.html",
        form=form,
        token=token,
        expires_in=expires_in
    )


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('admin_login'))


from flask import request

@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    search = request.args.get('search', '').strip()
    req_type = request.args.get('type', 'all')
    status_filter = request.args.get('status', 'all')

    query = POCRequest.query.order_by(POCRequest.created_at.desc())

    # Filter by Ticket ID (reference_id)
    if search:
        query = query.filter(POCRequest.reference_id.ilike(f"%{search}%"))

    # Filter by Request Type
    if req_type != 'all':
        query = query.filter(POCRequest.request_type == req_type)

    # Filter by Status
    if status_filter != 'all':
        query = query.filter(POCRequest.status == status_filter)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    end = min(page * per_page, pagination.total)

    upload_form = ProfilePictureForm()

    return render_template(
        "dashboard.html",
        requests=pagination.items,
        page=page,
        total_pages=pagination.pages,
        total_requests=pagination.total,
        per_page=per_page,
        end=end,
        current_search=search,
        current_type=req_type,
        current_status=status_filter,
        current_date=datetime.now(),
        form=upload_form
    )


@app.route('/update_status/<int:id>', methods=['POST'])
@login_required
@role_required('superadmin', 'admin', 'team')
def update_status(id):
    req = POCRequest.query.get_or_404(id)
    new_status = request.form.get("status")

    valid_statuses = ["Pending", "Acknowledged", "Declined", "Completed", "Reviewed"]  # ← Updated
    if new_status not in valid_statuses:
        flash("Invalid status selected.", "danger")
        return redirect(url_for('dashboard'))

    old_status = req.status
    req.status = new_status
    db.session.commit()

    # Shared styling variables
    header_bg = "#001f3f"
    primary_btn = "#007BFF"
    status_color = {
        "Acknowledged": "#28a745",   # ← Changed from "Approved"
        "Completed": "#28a745",
        "Declined": "#dc3545",
        "Pending": "#ffc107",
        "Reviewed": "#6c757d"
    }.get(new_status, "#6c757d")

    # Prepare dynamic status message safely
    type_lower = req.request_type.lower()

    if new_status == "Acknowledged":   # ← Changed from "Approved"
        status_message = (
            f"Your {type_lower} request has been acknowledged. "
            "Our team has received and reviewed it — we will reach out shortly to confirm next steps or schedule the session."
        )
    elif new_status == "Declined":
        status_message = (
            f"Unfortunately, your {type_lower} request has been declined at this time. "
            "If you have any questions or would like to provide more details, feel free to reply to this email."
        )
    elif new_status == "Completed":
        status_message = (
            f"Your {type_lower} session has been completed. "
            "Thank you for working with us — we hope it was valuable!"
        )
    elif new_status == "Pending":
        status_message = (
            f"Your {type_lower} request is Pending for further review. "
            "We will update you soon."
        )
    else:
        status_message = (
            f"We have reviewed and updated your {type_lower} request status. "
            "We will keep you informed of any next steps."
        )

    # === CLIENT EMAIL ===
    client_subject = f"Update: {req.request_type} Request (Ticket ID: {req.reference_id}) - {new_status}"

    client_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{client_subject} - Rago Global Solutions</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
        .container {{ max-width: 600px; margin: 30px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
        .header {{ background: {header_bg}; color: white; padding: 40px 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .content {{ padding: 40px 30px; color: #333; line-height: 1.7; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }}
        .btn {{ display: inline-block; background: {primary_btn}; color: white !important; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
        table {{ width: 100%; margin: 20px 0; border-collapse: collapse; }}
        td {{ padding: 10px 0; border-bottom: 1px solid #eee; }}
        .status-highlight {{ color: {status_color}; font-weight: bold; }}
        .ref-id {{ color: #001f3f; font-weight: bold; font-size: 1.2em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Request Update (Ticket ID: {req.reference_id})</h1>
        </div>
        <div class="content">
            <p>Dear <strong>{req.contact_person}</strong>,</p>
            <p>We wanted to let you know that your {type_lower} request with Rago Global Solutions has been reviewed and updated.</p>

            <h4 style="margin-top: 30px;">Ticket ID: <span class="ref-id">{req.reference_id}</span></h4>

            <h4>Status Details:</h4>
            <table>
                <tr><td><strong>Organization:</strong></td><td>{req.organization}</td></tr>
                <tr><td><strong>Contact Person:</strong></td><td>{req.contact_person}</td></tr>
                <tr><td><strong>Email:</strong></td><td>{req.email}</td></tr>
                <tr><td><strong>Phone:</strong></td><td>{req.phone or 'Not provided'}</td></tr>
                <tr><td><strong>Type:</strong></td><td>{req.request_type}</td></tr>
                <tr><td><strong>Status:</strong></td><td class="status-highlight">{new_status}</td></tr>
            </table>

            <p>{status_message}</p>

            <p style="margin-top: 30px; text-align: center;">
                <a href="https://ragoglobal.pythonanywhere.com" class="btn">Visit Our Website</a>
            </p>

            <p>If you have any questions or need further assistance, please reply directly to this email.</p>

            <p>Best regards,<br>
            <strong>Rago Global Solutions Team</strong><br>
            <a href="mailto:helpdesk.ragosa.tech@gmail.com">helpdesk.ragosa.tech@gmail.com</a><br>
            +234 813 887 9938</p>
        </div>
        <div class="footer">
            © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
            
        </div>
    </div>
</body>
</html>
"""

    client_plain = f"""Dear {req.contact_person},

Ticket ID: {req.reference_id}
Your {req.request_type} request for {req.organization} has been updated to: {new_status}

{status_message}

Best regards,
Rago Global Solutions Team
helpdesk.ragosa.tech@gmail.com
+234 813 887 9938
"""

    # === ADMIN NOTIFICATION ===
    admin_subject = f"[ADMIN] {req.request_type} Status Updated (Ticket ID: {req.reference_id}) - {new_status}"

    admin_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{admin_subject} - Rago Admin</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
        .container {{ max-width: 600px; margin: 30px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
        .header {{ background: #001f3f; color: white; padding: 40px 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .content {{ padding: 40px 30px; color: #333; line-height: 1.7; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }}
        table {{ width: 100%; margin: 20px 0; border-collapse: collapse; }}
        td {{ padding: 10px 0; border-bottom: 1px solid #eee; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{req.request_type} Status Updated (Ticket ID: {req.reference_id})</h1>
        </div>
        <div class="content">
            <p>Hello Admin,</p>
            <p>A {type_lower} request has just been updated in the system.</p>

            <h4 style="margin-top: 30px;">Update Details:</h4>
            <table>
                <tr><td><strong>Ticket ID:</strong></td><td>{req.reference_id}</td></tr>
                <tr><td><strong>Type:</strong></td><td>{req.request_type}</td></tr>
                <tr><td><strong>Organization:</strong></td><td>{req.organization}</td></tr>
                <tr><td><strong>Contact Person:</strong></td><td>{req.contact_person} ({req.email})</td></tr>
                <tr><td><strong>Phone:</strong></td><td>{req.phone or 'Not provided'}</td></tr>
                <tr><td><strong>Status Changed To:</strong></td><td>{new_status}</td></tr>
                <tr><td><strong>Updated By:</strong></td><td>{current_user.full_name}</td></tr>
            </table>

            <p style="margin-top: 30px; text-align: center;">
                <a href="{url_for('dashboard', _external=True)}" style="display: inline-block; background: #007BFF; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px;">View in Dashboard</a>
            </p>

            <p>Please review if further action is needed.</p>

            <p>Best regards,<br>
            <strong>Rago Admin System</strong></p>
        </div>
        <div class="footer">
            © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
            
        </div>
    </div>
</body>
</html>
"""

    admin_plain = f"""Ticket ID: {req.reference_id}
{req.request_type} request status updated:

Organization: {req.organization}
Contact: {req.contact_person} ({req.email})
New status: {new_status}
Updated by: {current_user.full_name}

Dashboard: {url_for('dashboard', _external=True)}
"""

    send_email(
        req.email,
        client_subject,
        plain_body=client_plain,
        html_body=client_html
    )

    send_email(
        "helpdesk.ragosa.tech@gmail.com",
        admin_subject,
        plain_body=admin_plain,
        html_body=admin_html
    )

    flash(f"Status updated to {new_status}. Client and admin notified (Ticket ID: {req.reference_id}).", "success")
    return redirect(url_for('dashboard'))

UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

from secrets import token_urlsafe  # for secure token generation

@app.route('/request-demo', methods=['GET', 'POST'])
def request_demo():
    form = PublicDemoForm()

    if form.validate_on_submit():
        # Save attachment immediately (if any) — we still need the file saved
        attachment_filename = None
        if form.attachment.data and form.request_type.data == 'POC':
            attachment_filename = save_unique_attachment(
                form.attachment.data,
                form.organization.data
            )

        # Prepare data to store temporarily in verification token
        form_data = {
            'organization': form.organization.data,
            'contact_person': form.contact_person.data,
            'email': form.email.data.strip().lower(),
            'phone': form.phone.data,
            'description': form.description.data,
            'request_type': form.request_type.data,
            'scheduled_date': form.scheduled_date.data.isoformat() if form.scheduled_date.data else None,
            'attachment_filename': attachment_filename,
        }

        # Create verification token (no POCRequest yet)
        token = token_urlsafe(32)
        verification = RequestVerificationToken(
            token=token,
            email=form.email.data.strip().lower(),
            form_data=form_data
        )
        db.session.add(verification)
        db.session.commit()

        verify_url = url_for('verify_request', token=token, _external=True)

        verification_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Verify Your {form.request_type.data} Request - Rago Global</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background: #f6f9fc; margin: 0; padding: 0; }}
                .container {{ max-width: 600px; margin: 40px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
                .header {{ background: #001f3f; color: white; padding: 40px 30px; text-align: center; }}
                .header h1 {{ margin: 0; font-size: 28px; }}
                .content {{ padding: 40px 30px; color: #333; line-height: 1.7; }}
                .btn {{ 
                    display: inline-block; 
                    background: #007BFF; 
                    color: white !important;
                    padding: 14px 40px; 
                    text-decoration: none; 
                    border-radius: 6px; 
                    font-size: 18px; 
                    margin: 20px 0; 
                    font-weight: 500;
                }}
                .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>One Last Step!</h1>
                </div>
                <div class="content">
                    <p>Dear <strong>{form.contact_person.data}</strong>,</p>
                    <p>Thank you for submitting your {form.request_type.data.lower()} request with Rago Global Solutions!</p>
                    <p>To complete your submission and ensure this is really you, please verify your email by clicking the button below:</p>
                    
                    <p style="text-align: center;">
                        <a href="{verify_url}" class="btn">Verify My Email & Submit Request</a>
                    </p>
                    
                    <p>If the button doesn't work, right click to copy and paste the link into your browser:</p>
                    
                    <p>This link expires in 24 hours.</p>
                    <p>If you didn't request this, you can safely ignore this email.</p>
                    
                    <p>Best regards,<br>
                    <strong>Rago Global Solutions Team</strong><br>
                    <a href="mailto:helpdesk.ragosa.tech@gmail.com">helpdesk.ragosa.tech@gmail.com</a><br>
                    +234 813 887 9938</p>
                </div>
                <div class="footer">
                    © 2026 Rago Global Solutions Ltd. All rights reserved.
                </div>
            </div>
        </body>
        </html>
        """

        send_email(
            form.email.data,
            f"Verify Your {form.request_type.data} Request - Rago Global Solutions",
            plain_body=f"Click here to verify: {verify_url}\n\nThis link expires in 24 hours.",
            html_body=verification_html
        )

        flash("Thank you! We've sent a verification email to your address. Please check your inbox (and spam folder) and click the link to confirm your request.", "info")
        return redirect(url_for('home'))

    return render_template("request_demo.html", form=form, existing_request=None)


@app.route('/verify-request/<token>')
def verify_request(token):
    verification = RequestVerificationToken.query.filter_by(token=token, used=False).first()
    
    if not verification:
        flash("This verification link is invalid.", "danger")
        return redirect(url_for('request_demo'))
    
    # ── Handle timezone-aware vs naive created_at safely ────────────────
    created_at = verification.created_at
    
    # If created_at is naive (old records), assume it was stored in UTC
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    
    # Now safe to compare both are aware (or both converted)
    now_utc = datetime.now(timezone.utc)
    
    if (now_utc - created_at) > timedelta(hours=24):
        flash("This verification link has expired. Please submit your request again.", "danger")
        return redirect(url_for('request_demo'))
    
    # ── Proceed with creating the POCRequest ─────────────────────────────
    form_data = verification.form_data
    
    # Generate unique reference ID
    reference_id = generate_reference_id()
    
    # Parse scheduled_date safely (handle None or string)
    scheduled_date_raw = form_data.get('scheduled_date')
    scheduled_date = None
    if scheduled_date_raw:
        try:
            scheduled_date = datetime.fromisoformat(scheduled_date_raw)
            # If parsed scheduled_date is naive → make it aware (assume UTC or local)
            if scheduled_date.tzinfo is None:
                scheduled_date = scheduled_date.replace(tzinfo=timezone.utc)
        except ValueError:
            # Invalid date format → ignore / log
            print("Warning: Invalid scheduled_date format in verification token")
    
    new_request = POCRequest(
        reference_id=reference_id,
        organization=form_data.get('organization', 'Unknown'),
        contact_person=form_data.get('contact_person', 'Unknown'),
        email=verification.email,
        phone=form_data.get('phone'),
        description=form_data.get('description', ''),
        request_type=form_data.get('request_type', 'Enquiry'),
        scheduled_date=scheduled_date,
        attachment=form_data.get('attachment_filename'),
        status="Pending",
        created_at=now_utc
    )
    
    db.session.add(new_request)
    verification.used = True
    db.session.commit()
    
    # Prepare attachment path for client email (if exists)
    client_attachment_path = None
    if new_request.attachment:
        client_attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], new_request.attachment)
        if not os.path.exists(client_attachment_path):
            client_attachment_path = None  # safety check
    
    # ── Send confirmation emails ────────────────────────────────────────
    type_lower = new_request.request_type.lower()
    is_enquiry = new_request.request_type == 'Enquiry'
    time_label = "Preferred Contact Time" if is_enquiry else "Preferred Date & Time"
    
    # Admin notification – include reference ID
    admin_subject = f"{new_request.request_type} Request Received (Ticket ID: {new_request.reference_id})"
    desc_preview = new_request.description[:800] + "..." if len(new_request.description) > 800 else new_request.description
    admin_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>{admin_subject} - Rago Admin</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
            .container {{ max-width: 600px; margin: 30px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
            .header {{ background: #001f3f; color: white; padding: 40px 30px; text-align: center; }}
            .header h1 {{ margin: 0; font-size: 28px; }}
            .content {{ padding: 40px 30px; color: #333; line-height: 1.7; }}
            .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }}
            table {{ width: 100%; margin: 20px 0; border-collapse: collapse; }}
            td {{ padding: 10px 0; border-bottom: 1px solid #eee; }}
            .desc-box {{ background: #f8f9fa; padding: 15px; border-left: 4px solid #007BFF; margin: 20px 0; white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>{admin_subject}</h1>
            </div>
            <div class="content">
                <p>A {type_lower} request has been verified and received.</p>
                <table>
                    <tr><td><strong>Ticket ID:</strong></td><td><strong>{new_request.reference_id}</strong></td></tr>
                    <tr><td><strong>Type:</strong></td><td>{new_request.request_type}</td></tr>
                    <tr><td><strong>Organization:</strong></td><td>{new_request.organization}</td></tr>
                    <tr><td><strong>Contact Person:</strong></td><td>{new_request.contact_person}</td></tr>
                    <tr><td><strong>Email:</strong></td><td>{new_request.email}</td></tr>
                    <tr><td><strong>Phone:</strong></td><td>{new_request.phone or 'Not provided'}</td></tr>
                    <tr><td><strong>{time_label}:</strong></td><td>{new_request.scheduled_date.strftime('%A, %d %B %Y at %H:%M') if new_request.scheduled_date else 'Not specified'}</td></tr>
                    <tr><td><strong>Attachment:</strong></td><td>{new_request.attachment or 'None'}</td></tr>
                </table>
                <h4 style="margin-top: 25px;">User's Message / Description:</h4>
                <div class="desc-box">{desc_preview}</div>
                <p style="margin-top: 30px; text-align: center;">
                    <a href="{url_for('dashboard', _external=True)}" style="display: inline-block; background: #007BFF; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px;">View in Dashboard</a>
                </p>
                <p>Best regards,<br>Rago Admin System</p>
            </div>
            <div class="footer">
                © 2026 Rago Global Solutions Ltd.
            </div>
        </div>
    </body>
    </html>
    """
    send_email(
        "helpdesk.ragosa.tech@gmail.com",
        admin_subject,
        plain_body=f"Reference: {new_request.reference_id}\n{new_request.request_type} request received from {new_request.organization}\n\nDescription:\n{new_request.description}\n\nAttachment: {new_request.attachment or 'None'}",
        html_body=admin_html,
        attachment_path=os.path.join(app.config['UPLOAD_FOLDER'], new_request.attachment)
                       if new_request.attachment else None
    )
    # Client confirmation – NOW WITH ATTACHMENT
    client_greeting = "Thank you for reaching out!" if is_enquiry else f"Thank you for your interest in Rago Global Solutions!"
    client_body_intro = f"Your {type_lower} request has been verified and received."
    client_body_next = "Our team has received your message and will get back to you soon." if is_enquiry else "Our team will review your request and get back to you within 24–48 hours."
    attachment_note = (
        '<p style="margin-top: 20px; font-style: italic;">'
        'We\'ve attached your uploaded document for your records.'
        '</p>'
    ) if new_request.attachment else ''
    client_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Your {new_request.request_type} Confirmed - Rago Global</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
            .container {{ max-width: 600px; margin: 30px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
            .header {{ background: #001f3f; color: white; padding: 40px 30px; text-align: center; }}
            .header h1 {{ margin: 0; font-size: 28px; }}
            .content {{ padding: 40px 30px; color: #333; line-height: 1.7; }}
            .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }}
            .btn {{ display: inline-block; background: #007BFF; color: white !important; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
            .highlight {{ color: #001f3f; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Your {new_request.request_type} Confirmed!</h1>
            </div>
            <div class="content">
                <p>Dear <strong>{new_request.contact_person}</strong>,</p>
                <p>{client_greeting}</p>
                <p>{client_body_intro}</p>
                <h4 style="margin-top: 30px;">Ticket ID: <span class="highlight">{new_request.reference_id}</span></h4>
                <table>
                    <tr><td><strong>Organization:</strong></td><td>{new_request.organization}</td></tr>
                    <tr><td><strong>Contact Person:</strong></td><td>{new_request.contact_person}</td></tr>
                    <tr><td><strong>Email:</strong></td><td>{new_request.email}</td></tr>
                    <tr><td><strong>Phone:</strong></td><td>{new_request.phone or 'Not provided'}</td></tr>
                    <tr><td><strong>{time_label}:</strong></td><td>{new_request.scheduled_date.strftime('%A, %d %B %Y at %H:%M') if new_request.scheduled_date else 'Not specified'}</td></tr>
                    <tr><td><strong>Attachment:</strong></td><td>{'Included below' if new_request.attachment else 'None'}</td></tr>
                </table>
                {attachment_note}
                <p>{client_body_next}</p>
                <p style="margin-top: 30px;">
                    <a href="https://ragoglobal.pythonanywhere.com" class="btn">Visit Our Website</a>
                </p>
                <p>Best regards,<br>
                <strong>Rago Global Solutions Team</strong><br>
                <a href="mailto:helpdesk.ragosa.tech@gmail.com">helpdesk.ragosa.tech@gmail.com</a><br>
                +234 813 887 9938</p>
            </div>
            <div class="footer">
                © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
               
            </div>
        </div>
    </body>
    </html>
    """
    send_email(
        new_request.email,
        f"Your {new_request.request_type} Confirmed (Ticket ID: {new_request.reference_id}) - Rago Global Solutions",
        plain_body=f"Ticket ID: {new_request.reference_id}\nYour request has been verified and received. We'll be in touch soon.\n{'Your uploaded document is attached.' if new_request.attachment else ''}",
        html_body=client_html,
        attachment_path=client_attachment_path # ← THIS IS THE KEY CHANGE
    )
    flash(f"Thank you! Your request has been verified and submitted successfully. Ticket ID: {new_request.reference_id}", "success")
    return redirect(url_for('home'))
# New form for OTP
class OTPVerifyForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit_otp = SubmitField('Verify & Fetch Requests')


@app.route('/api/notifications')
@login_required
@role_required('superadmin', 'admin', 'team', 'viewer')
def api_notifications():
    pending = POCRequest.query.filter_by(status="Pending").count()
    pending_requests = POCRequest.query.filter_by(status="Pending")\
        .order_by(POCRequest.created_at.desc()).limit(5).all()

    followup = POCRequest.query.filter_by(status="Follow-up").count()
    followup_requests = POCRequest.query.filter_by(status="Follow-up")\
        .order_by(POCRequest.created_at.desc()).limit(5).all()

    return jsonify({
        "pending_count": pending,
        "pending_requests": [{
            "id": r.id,
            "reference_id": r.reference_id,
            "organization": r.organization,
            "request_type": r.request_type
        } for r in pending_requests],
        "followup_count": followup,
        "followup_requests": [{
            "id": f.id,
            "reference_id": f.reference_id,
            "organization": f.organization
        } for f in followup_requests]
    })


# ── Route: Client follow-up page with OTP verification ──
@app.route('/follow-up', methods=['GET', 'POST'])
def follow_up():
    lookup_form = FollowUpLookupForm()
    otp_form = OTPVerifyForm()
    message_form = FollowUpMessageForm()
    
    # Try to restore state from session
    step = session.get('followup_step', 'lookup')
    reference_id = session.get('followup_ref')
    followup_email = session.get('followup_email')
    otp_id = session.get('followup_otp_id')
    existing_requests = []
    
    # ────────────────────────────────────────────────────────────────
    # Validate if current follow-up session is still usable
    # ────────────────────────────────────────────────────────────────
    if step in ('verify', 'message') and otp_id:
        otp_record = OTPCode.query.get(otp_id)
      
        if not otp_record:
            # OTP row was deleted → treat as expired / invalid
            session.pop('followup_otp_id', None)
            flash("Verification code record not found. Please request a new one.", "warning")
            step = 'verify'  # stay on OTP page, let user retry lookup if needed
      
        elif otp_record.used:
            # OTP was already used → normal after successful verification
            if step == 'message':
                # already verified → keep going
                pass
            else:
                # somehow still on verify step with used OTP → force back to lookup
                session['followup_step'] = 'lookup'
                flash("This code has already been used. Please enter your Ticket ID again.", "info")
                step = 'lookup'
      
        else:
            # OTP exists and is unused → check age
            # FIX: Make created_at timezone-aware if it is naive
            created_at = otp_record.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            
            age = datetime.now(timezone.utc) - created_at
            if age > timedelta(minutes=15):
                # expired unused OTP → clean only OTP part
                session.pop('followup_otp_id', None)
                otp_record.used = True  # mark it anyway to prevent reuse
                db.session.commit()
                flash("Your verification code has expired. Please enter your Ticket ID to get a new one.", "warning")
                step = 'lookup'
            # else: valid unused OTP → keep current step (verify or message)
    
    else:
        # no otp_id or not in verify/message → default to lookup
        step = 'lookup'
        reference_id = None
        followup_email = None
    
    # ────────────────────────────────────────────────────────────────
    # POST handling
    # ────────────────────────────────────────────────────────────────
    if request.method == 'POST':
        # ── Resend OTP ─────────────────────────────────────────────────
        if 'resend_otp' in request.form:
            if step == 'verify' and followup_email:
                # Basic rate limit: don't allow resend if last OTP < 30 seconds old
                if otp_id:
                    last_otp = OTPCode.query.get(otp_id)
                    # Also make last_otp.created_at safe
                    last_created = last_otp.created_at
                    if last_created.tzinfo is None:
                        last_created = last_created.replace(tzinfo=timezone.utc)
                    if (datetime.now(timezone.utc) - last_created).total_seconds() < 30:
                        flash("Please wait a moment before requesting a new code.", "warning")
                        return redirect(url_for('follow_up'))
                
                new_code = ''.join(random.choices(string.digits, k=6))
                new_otp_record = OTPCode(
                    user_id='system',
                    code=new_code,
                    created_at=datetime.now(timezone.utc),
                    used=False
                )
                db.session.add(new_otp_record)
                db.session.commit()
                
                otp_subject = "Rago Global Solutions - New Verification Code"
                otp_html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <title>{otp_subject}</title>
                    <style>
                        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
                        .container {{ max-width: 600px; margin: 40px auto; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 8px 30px rgba(0,0,0,0.1); }}
                        .header {{ background: linear-gradient(135deg, #001f3f, #003366); color: white; padding: 50px 40px; text-align: center; }}
                        .header h1 {{ margin: 0; font-size: 32px; }}
                        .content {{ padding: 50px 40px; color: #333; line-height: 1.8; }}
                        .otp-box {{ font-size: 48px; font-weight: bold; letter-spacing: 12px; color: #007BFF; background: #f0f7ff; padding: 20px; text-align: center; border-radius: 12px; margin: 30px 0; box-shadow: inset 0 2px 10px rgba(0,123,255,0.1); }}
                        .btn {{ display: inline-block; background: #007BFF; color: white !important; padding: 14px 40px; text-decoration: none; border-radius: 50px; font-size: 18px; margin: 30px 0; }}
                        .footer {{ background: #001f3f; color: white; padding: 30px; text-align: center; font-size: 14px; }}
                            @media only screen and (max-width: 600px) {{
                            body, p, div {{ font-size: 15px !important; line-height: 1.6 !important; }}
                            h1 {{ font-size: 24px !important; }}
                            .otp-box {{
                                font-size: 36px !important;
                                letter-spacing: 10px !important;
                                padding: 20px !important;
                                margin: 30px 0 !important;
                            }}
                            .btn {{ font-size: 16px !important; padding: 12px 40px !important; }}
                            .content {{ padding: 30px 20px !important; }}
                            .header {{ padding: 50px 20px 40px !important; }}
                            .footer {{ font-size: 13px !important; padding: 25px !important; }}
                        }}
                        @media only screen and (max-width: 400px) {{
                            .otp-box {{ font-size: 32px !important; letter-spacing: 8px !important; }}
                        }}
                    
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>New Verification Code</h1>
                        </div>
                        <div class="content">
                            <p>Dear Valued Client,</p>
                            <p>You requested a new code. Here is your new verification code:</p>
                            <div class="otp-box">{new_code}</div>
                            <p>This code is valid for <strong>10 minutes</strong>. Do not share it with anyone.</p>
                            <p style="text-align: center;">
                                <a href="{url_for('follow_up', _external=True)}" class="btn">Continue to Follow-up</a>
                            </p>
                            <p>If you did not request this, please ignore this email or contact support.</p>
                            <p>Best regards,<br>
                            <strong>Rago Global Solutions Team</strong><br>
                            <a href="mailto:helpdesk.ragosa.tech@gmail.com" style="color:#007BFF;">helpdesk.ragosa.tech@gmail.com</a><br>
                            +234 813 887 9938</p>
                        </div>
                        <div class="footer">
                            © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
                        </div>
                    </div>
                </body>
                </html>
                """
                send_email(
                    followup_email,
                    otp_subject,
                    plain_body=f"Your new verification code: {new_code}\nValid for 10 minutes.",
                    html_body=otp_html
                )
                # Update session with new OTP ID
                session['followup_otp_id'] = new_otp_record.id
                flash("A new 6-digit verification code has been sent to your email.", "success")
                return redirect(url_for('follow_up'))
            else:
                flash("Cannot resend OTP right now. Please try again later.", "danger")

        # ── 1. Lookup ticket ID → send OTP ───────────────────────────
        if 'submit_lookup' in request.form:
            if lookup_form.validate_on_submit():
                ref_input = lookup_form.reference_id.data.strip().upper()
                requests_list = POCRequest.query.filter_by(reference_id=ref_input)\
                                               .order_by(POCRequest.created_at.desc()).all()
                if not requests_list:
                    flash(f"No requests found with Ticket ID: {ref_input}", "warning")
                else:
                    email = requests_list[0].email
                    otp_code = ''.join(random.choices(string.digits, k=6))
                    otp_record = OTPCode(
                        user_id='system',
                        code=otp_code,
                        created_at=datetime.now(timezone.utc),
                        used=False
                    )
                    db.session.add(otp_record)
                    db.session.commit()
                    
                    otp_subject = "Rago Global Solutions - Your Verification Code"
                    otp_html = f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset="utf-8">
                        <title>{otp_subject}</title>
                        <style>
                            body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
                            .container {{ max-width: 600px; margin: 40px auto; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 8px 30px rgba(0,0,0,0.1); }}
                            .header {{ background: linear-gradient(135deg, #001f3f, #003366); color: white; padding: 50px 40px; text-align: center; }}
                            .header h1 {{ margin: 0; font-size: 32px; }}
                            .content {{ padding: 50px 40px; color: #333; line-height: 1.8; }}
                            .otp-box {{ font-size: 48px; font-weight: bold; letter-spacing: 12px; color: #007BFF; background: #f0f7ff; padding: 20px; text-align: center; border-radius: 12px; margin: 30px 0; box-shadow: inset 0 2px 10px rgba(0,123,255,0.1); }}
                            .btn {{ display: inline-block; background: #007BFF; color: white !important; padding: 14px 40px; text-decoration: none; border-radius: 50px; font-size: 18px; margin: 30px 0; }}
                            .footer {{ background: #001f3f; color: white; padding: 30px; text-align: center; font-size: 14px; }}
                        
                            @media only screen and (max-width: 600px) {{
                                body, p, div {{ font-size: 15px !important; line-height: 1.6 !important; }}
                                h1 {{ font-size: 24px !important; }}
                                .otp-box {{
                                    font-size: 36px !important;
                                    letter-spacing: 10px !important;
                                    padding: 20px !important;
                                    margin: 30px 0 !important;
                                }}
                                .btn {{ font-size: 16px !important; padding: 12px 40px !important; }}
                                .content {{ padding: 30px 20px !important; }}
                                .header {{ padding: 50px 20px 40px !important; }}
                                .footer {{ font-size: 13px !important; padding: 25px !important; }}
                            }}
                            @media only screen and (max-width: 400px) {{
                                .otp-box {{ font-size: 32px !important; letter-spacing: 8px !important; }}
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h1>Your Verification Code</h1>
                            </div>
                            <div class="content">
                                <p>Dear Valued Client,</p>
                                <p>You requested to follow up on your existing ticket. Please use the code below to securely access your request history:</p>
                                <div class="otp-box">{otp_code}</div>
                                <p>This code is valid for <strong>10 minutes</strong>. Do not share it with anyone.</p>
                                <p style="text-align: center;">
                                    <a href="{url_for('follow_up', _external=True)}" class="btn">Continue to Follow-up</a>
                                </p>
                                <p>If you did not request this, please ignore this email or contact support.</p>
                                <p>Best regards,<br>
                                <strong>Rago Global Solutions Team</strong><br>
                                <a href="mailto:helpdesk.ragosa.tech@gmail.com" style="color:#007BFF;">helpdesk.ragosa.tech@gmail.com</a><br>
                                +234 813 887 9938</p>
                            </div>
                            <div class="footer">
                                © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                    send_email(
                        email,
                        otp_subject,
                        plain_body=f"Your verification code: {otp_code}\nValid for 10 minutes.",
                        html_body=otp_html
                    )
                    session['followup_step'] = 'verify'
                    session['followup_ref'] = ref_input
                    session['followup_email'] = email
                    session['followup_otp_id'] = otp_record.id
                    flash(f"A 6-digit verification code has been sent to your email. Please check your inbox (and spam folder).", "info")
                    return redirect(url_for('follow_up'))

        # ── 2. Verify OTP ───────────────────────────────────────────────
        elif 'submit_otp' in request.form:
            if otp_form.validate_on_submit():
                current_otp_id = session.get('followup_otp_id')
                if not current_otp_id:
                    flash("No active verification session. Please start again.", "danger")
                    return redirect(url_for('follow_up'))
                
                otp_record = OTPCode.query.get(current_otp_id)
                if not otp_record or otp_record.used:
                    flash("Invalid or already used verification session.", "danger")
                    return redirect(url_for('follow_up'))
                
                # FIX: Make created_at aware if naive
                created_at = otp_record.created_at
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                
                if datetime.now(timezone.utc) - created_at > timedelta(minutes=15):
                    flash("This verification code has expired. Please request a new one.", "warning")
                    return redirect(url_for('follow_up'))
                
                if otp_record.code == otp_form.otp.data.strip():
                    otp_record.used = True
                    db.session.commit()
                    session['followup_step'] = 'message'
                    flash("Verification successful! You can now send your follow-up message.", "success")
                    return redirect(url_for('follow_up'))
                else:
                    flash("Incorrect code. Please try again.", "danger")

        # ── 3. Submit follow-up message ─────────────────────────────────
        elif 'submit_message' in request.form:
            ref = session.get('followup_ref') or request.form.get('reference_id')
            if not ref:
                flash("No active ticket session found. Please start over.", "danger")
                return redirect(url_for('follow_up'))
            
            parent = POCRequest.query.filter_by(reference_id=ref).first()
            if not parent:
                flash("Ticket not found.", "danger")
                return redirect(url_for('follow_up'))
            
            if message_form.validate_on_submit():
                followup = POCRequest(
                    reference_id=ref,
                    organization=parent.organization,
                    contact_person=parent.contact_person,
                    email=parent.email,
                    phone=parent.phone,
                    description=message_form.message.data,
                    request_type="Follow-up",
                    status="Follow-up",
                    created_at=datetime.now(timezone.utc)
                )
                if message_form.attachment.data:
                    filename = secure_filename(message_form.attachment.data.filename)
                    safe_name = f"followup-{ref}-{filename}"
                    path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
                    message_form.attachment.data.save(path)
                    followup.attachment = safe_name
                
                db.session.add(followup)
                db.session.commit()
                
                received_subject = f"Follow-up Received – Ticket {ref}"
                received_html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <title>{received_subject}</title>
                    <style>
                        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
                        .container {{ max-width: 600px; margin: 40px auto; background: white; border-radius: 16px; overflow: hidden; box-shadow: 0 8px 30px rgba(0,0,0,0.1); }}
                        .header {{ background: linear-gradient(135deg, #28a745, #1e7e34); color: white; padding: 60px 40px; text-align: center; }}
                        .header h1 {{ margin: 0; font-size: 36px; }}
                        .content {{ padding: 50px 40px; color: #333; line-height: 1.8; text-align: center; }}
                        .icon-check {{ font-size: 90px; color: #28a745; margin: 40px 0; }}
                        .btn {{ display: inline-block; background: #28a745; color: white !important; padding: 16px 50px; text-decoration: none; border-radius: 50px; font-size: 20px; margin: 40px 0; box-shadow: 0 4px 15px rgba(40,167,69,0.3); }}
                        .footer {{ background: #001f3f; color: white; padding: 30px; text-align: center; font-size: 14px; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Follow-up Received!</h1>
                        </div>
                        <div class="content">
                            <div class="icon-check">✔</div>
                            <p>Dear <strong>{parent.contact_person}</strong>,</p>
                            <p>Thank you! Your follow-up message for ticket <strong>{ref}</strong> has been successfully received.</p>
                            <p>Our team is reviewing your update and will get back to you as soon as possible.</p>
                            <p style="margin: 40px 0;">
                                <a href="https://ragoglobal.pythonanywhere.com" class="btn">Visit Our Website</a>
                            </p>
                            <p>Ticket ID: <strong>{ref}</strong><br>
                            Please keep this reference for any future communication.</p>
                            <p>Best regards,<br>
                            <strong>Rago Global Solutions Team</strong><br>
                            <a href="mailto:helpdesk.ragosa.tech@gmail.com" style="color:#007BFF;">helpdesk.ragosa.tech@gmail.com</a><br>
                            +234 813 887 9938</p>
                        </div>
                        <div class="footer">
                            © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
                        </div>
                    </div>
                </body>
                </html>
                """
                send_email(
                    parent.email,
                    received_subject,
                    plain_body=f"Dear {parent.contact_person},\n\nYour follow-up for ticket {ref} has been received.\nWe'll respond soon.\n\nBest regards,\nRago Team",
                    html_body=received_html
                )
                send_email(
                    "helpdesk.ragosa.tech@gmail.com",
                    f"[FOLLOW-UP] New message on Ticket {ref}",
                    f"New follow-up:\nTicket: {ref}\nFrom: {parent.email}\nMessage preview: {message_form.message.data[:200]}..."
                )
                flash("Your follow-up message has been sent successfully!", "success")
                
                # Clear session only after successful submission
                session.clear()
                # Redirect with flag so template can show Toastify
                return redirect(url_for('follow_up') + '?msg_sent=1')

    # ── Load existing requests only when showing message step ───────────
    if step == 'message' and reference_id:
        existing_requests = POCRequest.query.filter_by(reference_id=reference_id)\
                                           .order_by(POCRequest.created_at.desc()).all()

    return render_template('follow_up.html',
                          lookup_form=lookup_form,
                          otp_form=otp_form,
                          message_form=message_form,
                          step=step,
                          reference_id=reference_id,
                          existing_requests=existing_requests,
                          followup_email=followup_email)


# ── Helper endpoint for JavaScript to call on page leave/refresh ────────
@app.route('/follow-up/cleanup-session', methods=['POST'])
def followup_session_cleanup():
    for key in ['followup_step', 'followup_ref', 'followup_email', 'followup_otp_id']:
        session.pop(key, None)
    return '', 204

@app.route('/schedule/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('superadmin', 'admin', 'team')
def schedule_demo(id):
    req = POCRequest.query.get_or_404(id)
    form = ScheduleForm()

    if form.validate_on_submit():
        req.scheduled_date = form.scheduled_date.data
        req.status = "Scheduled"

        attachment_filename = None
        attachment_path = None

        # Handle optional attachment
        if form.attachment.data:
            filename = secure_filename(form.attachment.data.filename)
            attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            form.attachment.data.save(attachment_path)
            attachment_filename = filename

        db.session.commit()

        ics_path = generate_ics_file(req)

        # Customized HTML email – include reference ID prominently
        schedule_subject = f"Your {req.request_type} Scheduled (Ticket ID: {req.reference_id}) – Rago Global Solutions"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>{schedule_subject}</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
                .container {{ max-width: 600px; margin: 30px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
                .header {{ background: #001f3f; color: white; padding: 40px 30px; text-align: center; }}
                .header h1 {{ margin: 0; font-size: 28px; }}
                .content {{ padding: 40px 30px; color: #333; line-height: 1.7; }}
                .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }}
                .btn {{ display: inline-block; background: #007BFF; color: white !important; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
                table {{ width: 100%; margin: 20px 0; border-collapse: collapse; }}
                td {{ padding: 10px 0; border-bottom: 1px solid #eee; }}
                .highlight {{ color: #007BFF; font-weight: bold; }}
                .ref-id {{ color: #001f3f; font-weight: bold; font-size: 1.2em; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Your {req.request_type} is Confirmed! (Ticket ID: {req.reference_id})</h1>
                </div>
                <div class="content">
                    <p>Dear <strong>{req.contact_person}</strong>,</p>
                    <p>Great news! Your requested {req.request_type.lower()} with Rago Global Solutions has been officially scheduled.</p>

                    <h4 style="margin-top: 30px;">Ticket ID: <span class="ref-id">{req.reference_id}</span></h4>

                    <h4>Scheduled Details:</h4>
                    <table>
                        <tr><td><strong>Type:</strong></td><td>{req.request_type}</td></tr>
                        <tr><td><strong>Organization:</strong></td><td>{req.organization}</td></tr>
                        <tr><td><strong>Contact Person:</strong></td><td>{req.contact_person}</td></tr>
                        <tr><td><strong>Email:</strong></td><td>{req.email}</td></tr>
                        <tr><td><strong>Phone:</strong></td><td>{req.phone or 'Not provided'}</td></tr>
                        <tr><td><strong>Date & Time:</strong></td><td class="highlight">{req.scheduled_date.strftime('%A, %d %B %Y at %H:%M')}</td></tr>
                        <tr><td><strong>Attachment:</strong></td><td>{attachment_filename or 'None'}</td></tr>
                    </table>

                    <p>Please find the calendar invite (.ics file) attached to this email — add it to your calendar to avoid missing the session.</p>

                    <p>We’re looking forward to {
                        'showing you the platform and answering all your questions'
                        if req.request_type == 'Demo' else
                        'working through the proof of concept together'
                        if req.request_type == 'POC' else
                        'discussing your enquiry in detail'
                    }!</p>

                    <p style="margin-top: 30px; text-align: center;">
                        <a href="https://ragoglobal.pythonanywhere.com" class="btn">Visit Our Website</a>
                    </p>

                    <p>If you need to reschedule or have any questions before the {req.request_type.lower()}, feel free to reply to this email quoting your reference ID: <strong>{req.reference_id}</strong>.</p>

                    <p>Best regards,<br>
                    <strong>Rago Global Solutions Team</strong><br>
                    <a href="mailto:helpdesk.ragosa.tech@gmail.com">helpdesk.ragosa.tech@gmail.com</a><br>
                    +234 813 887 9938</p>
                </div>
                <div class="footer">
                    © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
                    
                </div>
            </div>
        </body>
        </html>
        """

        plain_body = f"""Dear {req.contact_person},

Ticket ID: {req.reference_id}
Your {req.request_type} is now scheduled for:
📅 {req.scheduled_date.strftime('%A, %d %B %Y at %H:%M')}

Attachment: {attachment_filename or 'None'}
Calendar invite attached.

We look forward to the {req.request_type.lower()}!

Best regards,
Rago Global Solutions
helpdesk.ragosa.tech@gmail.com
+234 813 887 9938
"""

        send_email(
            req.email,
            schedule_subject,
            plain_body=plain_body,
            html_body=html_body,
            attachment_path=ics_path,
            extra_attachment=attachment_path
        )

        flash(f"{req.request_type} scheduled and notification sent to client successfully (Ticket ID: {req.reference_id}).", "success")
        return redirect(url_for('dashboard'))

    return render_template("schedule.html", form=form, request=req)

# Protected default superadmin username
PROTECTED_SUPERADMIN_USERNAME = "admin"  # Change if your default has a different username


@app.route('/admin/users')
@login_required
@role_required('superadmin', 'admin')
def manage_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@role_required('superadmin', 'admin')
def create_user():
    form = CreateUserForm()
    if form.validate_on_submit():
        new_user = User(
            username=form.username.data.strip(),
            full_name=form.full_name.data.strip() or None,
            email=form.email.data.strip().lower(),
            role=form.role.data.strip()
        )
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash(f"User '{new_user.username}' ({new_user.full_name or 'no name'}) created.", "success")
        return redirect(url_for('manage_users'))
    return render_template('admin_user_form.html', form=form, title="Create New User")


# Protected default superadmin username (only this one gets extra lock)
PROTECTED_SUPERADMIN_USERNAME = "admin"  # change if needed


@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('superadmin', 'admin')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    # Define these at function scope so they're always available
    is_admin = (current_user.role == 'admin')
    is_superadmin = (current_user.role == 'superadmin')

    # Determine if this is a self-edit attempt
    is_self_edit = (user.id == current_user.id)

    # ── Access control: who can edit whom ───────────────────────────────────────
    if is_self_edit:
        # Only superadmin is allowed to edit themselves
        if not is_superadmin:
            flash("You are not allowed to edit your own profile.", "warning")
            return redirect(url_for('manage_users'))
        # Superadmin → allowed to edit self
    else:
        # Editing someone else
        # Protect the primary (hardcoded) superadmin account from everyone
        if user.username == PROTECTED_SUPERADMIN_USERNAME:
            flash("This is the primary system owner account and cannot be edited.", "danger")
            return redirect(url_for('manage_users'))

        # Only superadmin can edit other superadmin accounts
        if user.role == 'superadmin' and not is_superadmin:
            flash("Only superadmin can edit other superadmin accounts.", "danger")
            return redirect(url_for('manage_users'))

    # ── Form setup ──────────────────────────────────────────────────────────────
    form = EditUserForm(user_id=user.id)

    if request.method == 'GET':
        form.username.data = user.username
        form.full_name.data = user.full_name
        form.email.data = user.email
        form.role.data = user.role

    if form.validate_on_submit():
        # Username, full_name, email → superadmin only (or self if superadmin)
        if is_superadmin:
            user.username = form.username.data.strip()
            user.full_name = form.full_name.data.strip() or None
            user.email = form.email.data.strip().lower()

        # Role change:
        # - Superadmin can change anyone's role
        # - Admin can change role of non-superadmin users
        if is_superadmin or (is_admin and user.role != 'superadmin'):
            user.role = form.role.data.strip()

        # Password reset: allowed for both admin and superadmin
        if form.password.data:
            user.set_password(form.password.data)

        db.session.commit()
        flash(f"User '{user.username}' updated successfully.", "success")
        return redirect(url_for('manage_users'))

    # ── Render form ─────────────────────────────────────────────────────────────
    return render_template(
        'admin_user_form.html',
        form=form,
        title="Edit User",
        user=user,
        is_admin=is_admin,
        is_self_edit=is_self_edit  # optional: pass if you want conditional UI
    )


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required('superadmin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    # Prevent self-deletion
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for('manage_users'))

    # Protect default superadmin account
    if user.username == PROTECTED_SUPERADMIN_USERNAME:
        flash("This is the primary system owner account and cannot be deleted.", "danger")
        return redirect(url_for('manage_users'))

    db.session.delete(user)
    db.session.commit()
    flash(f"User '{user.username}' deleted successfully.", "success")
    return redirect(url_for('manage_users'))

# =========================
# INITIALIZE DATABASE + DEFAULT ADMIN
# =========================
with app.app_context():
    print("Creating all tables...")
    db.create_all()
    print("Tables created (or already exist).")

    print("Checking for default admin...")
    try:
        existing_admin = User.query.filter_by(username="admin").first()
        if not existing_admin:
            print("No admin found → creating default admin")
            admin = User(
                username="admin",
                email=os.getenv("ADMIN_EMAIL", "helpdesk.ragosa.tech@gmail.com"),
                role="admin"
            )
            admin.set_password(os.getenv("ADMIN_PASSWORD", "GodspowerRachealGabriellaElianaOmoruyi"))
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created successfully.")
        else:
            print("Admin user already exists.")
    except Exception as e:
        print("Error during admin check/creation:", str(e))

if __name__ == "__main__":
    print("Starting Flask app...")
    app.run(debug=os.getenv("FLASK_ENV", "development") != "production")