from flask import Flask, jsonify, render_template, request, flash, redirect, session, url_for
from flask_wtf import FlaskForm
from flask_migrate import Migrate  # ← keep this import
from wtforms import StringField, TextAreaField, SubmitField, DateTimeLocalField, PasswordField, ValidationError
from wtforms.validators import DataRequired, Email, Length, Optional
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from dotenv import load_dotenv
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
# LOAD ENVIRONMENT VARIABLES
# =========================
load_dotenv()

# =========================
# APP CONFIGURATION
# =========================
app = Flask(__name__,
            template_folder='../templates',
            static_folder='../static')

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") or os.urandom(32).hex()

# PostgreSQL (Neon) on Vercel / production
# Local fallback to SQLite only if DATABASE_URL not set
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    "DATABASE_URL",
    "sqlite:///rago_app.db"  # only used when running locally without env var
)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv("FLASK_ENV", "development") == "production"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=14)

db = SQLAlchemy(app)

migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

# =========================
# EMAIL CONFIG
# =========================
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
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default="admin")  # admin, viewer, superadmin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)


class OTPCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False)


class ResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class POCRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    organization = db.Column(db.String(150), nullable=False)
    contact_person = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(30))
    description = db.Column(db.Text, nullable=False)
    request_type = db.Column(db.String(20), nullable=False)  # 'Enquiry', 'POC', 'Demo'
    attachment = db.Column(db.String(255))  # filename of uploaded doc
    status = db.Column(db.String(30), default="Pending")
    scheduled_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RequestVerificationToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    form_data = db.Column(db.JSON, nullable=False)  # store serialized form data
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<VerificationToken {self.token} for {self.email}>"
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# =========================
# FORMS
# =========================
class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    company = StringField('Company Name (Optional)', validators=[Length(max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[Length(max=20)])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=10, max=1000)])
    submit = SubmitField('Send Message')


class POCRequestForm(FlaskForm):
    organization = StringField('Organization', validators=[DataRequired()])
    contact_person = StringField('Contact Person', validators=[DataRequired()])
    email = StringField('Official Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone')
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Submit Request')


class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class Verify2FAForm(FlaskForm):
    code = StringField('Verification Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Reset Password')


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
        validators=[FileAllowed(['pdf', 'doc', 'docx', 'zip'], 'Only PDF, Word, or ZIP allowed')]
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
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=10, max=5000)])
    submit = SubmitField('Send Reply')

class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    role = StringField('Role', validators=[DataRequired()], default="admin")  # can be select later
    submit = SubmitField('Create User')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data.strip()).first():
            raise ValidationError('Username already exists.')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.strip().lower()).first():
            raise ValidationError('Email already in use.')

class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = StringField('Role', validators=[DataRequired()])
    password = PasswordField('New Password (leave blank to keep current)', validators=[Optional(), Length(min=8)])
    submit = SubmitField('Update User')

    def validate_username(self, field):
        user = User.query.get(self.id.data) if hasattr(self, 'id') else None
        existing = User.query.filter_by(username=field.data.strip()).first()
        if existing and existing != user:
            raise ValidationError('Username already exists.')

    def validate_email(self, field):
        user = User.query.get(self.id.data) if hasattr(self, 'id') else None
        existing = User.query.filter_by(email=field.data.strip().lower()).first()
        if existing and existing != user:
            raise ValidationError('Email already in use.')
        
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


# =========================
# EMAIL UTILITIES
# =========================
def send_email(to_email, subject, plain_body, html_body=None, attachment_path=None, extra_attachment=None):
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        print("Email credentials not configured.")
        return

    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to_email
        msg['Subject'] = subject

        # Plain text version (fallback)
        msg.attach(MIMEText(plain_body, 'plain'))

        # HTML version (preferred)
        if html_body:
            msg.attach(MIMEText(html_body, 'html'))

        # Handle main attachment (ICS)
        if attachment_path and os.path.exists(attachment_path):
            part = MIMEBase('application', "octet-stream")
            with open(attachment_path, 'rb') as f:
                part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(attachment_path)}"')
            msg.attach(part)

        # Handle extra attachment (PDF/Excel/Word/image)
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
        server.sendmail(app.config['MAIL_USERNAME'], to_email, msg.as_string())
        server.quit()
        print(f"[EMAIL SENT] to {to_email} - Subject: {subject}")
    except Exception as e:
        print("Email Error:", str(e))

@app.route('/api/pending-count')
@login_required
@role_required('admin', 'viewer')
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

@app.route('/reply/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'viewer')
def reply_client(id):
    req = POCRequest.query.get_or_404(id)
    form = ReplyClientForm()

    if form.validate_on_submit():
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Message from Rago Global Solutions</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
                .container {{ max-width: 600px; margin: 30px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
                .header {{ background: #001f3f; color: white; padding: 40px 30px; text-align: center; }}
                .header h1 {{ margin: 0; font-size: 28px; }}
                .content {{ padding: 40px 30px; color: #333; line-height: 1.7; }}
                .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }}
                .btn {{ display: inline-block; background: #007BFF; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Message from Rago Global</h1>
                </div>
                <div class="content">
                    <p>Dear <strong>{req.contact_person}</strong>,</p>
                    <p>{form.message.data}</p>   <!-- ← remove | safe here -->
                    <p style="margin-top: 30px; text-align: center;">
                        <a href="https://rago-tech.vercel.app" class="btn">Visit Our Website</a>
                    </p>
                    <p>Best regards,<br>
                    <strong>Rago Global Solutions Team</strong><br>
                    <a href="mailto:helpdesk.ragosa.tech@gmail.com">helpdesk.ragosa.tech@gmail.com</a><br>
                    +234 813 887 9938</p>
                </div>
                <div class="footer">
                    © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
                    Built with passion in Lagos, Nigeria
                </div>
            </div>
        </body>
        </html>
        """

        send_email(
            req.email,
            form.subject.data,
            plain_body=form.message.data,
            html_body=html_body
        )

        flash(f"Reply sent successfully to {req.email}.", "success")
        return redirect(url_for('dashboard'))

    return render_template("reply_client.html", form=form, request=req)

def generate_ics_file(request_obj):
    os.makedirs(app.static_folder, exist_ok=True)
    
    # Make filename type-specific
    type_prefix = request_obj.request_type.lower()
    filename = f"{type_prefix}_schedule_{uuid.uuid4()}.ics"
    filepath = os.path.join(app.static_folder, filename)

    start = request_obj.scheduled_date
    end = start + timedelta(hours=1)

    # Make event title and description type-specific
    event_title = f"Core Banking {request_obj.request_type} - Rago Global Solutions"
    event_desc = (
        f"{request_obj.request_type} Session with {request_obj.organization}\n"
        f"Contact: {request_obj.contact_person} ({request_obj.email})\n"
        f"Phone: {request_obj.phone or 'Not provided'}\n\n"
        "Please be prepared with any questions or requirements.\n"
        "Join via the link or details that will be shared closer to the time."
    )

    content = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Rago Global Solutions//EN
BEGIN:VEVENT
UID:{uuid.uuid4()}
SUMMARY:{event_title}
DTSTART:{start.strftime("%Y%m%dT%H%M%S")}
DTEND:{end.strftime("%Y%m%dT%H%M%S")}
DESCRIPTION:{event_desc.replace('\n', '\\n')}
LOCATION:Online / Virtual Meeting
END:VEVENT
END:VCALENDAR"""

    with open(filepath, "w") as f:
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
        user = User.query.filter_by(username=form.username.data.strip()).first()

        if not user or not user.check_password(form.password.data):
            flash("Invalid username or password.", "danger")
            return render_template("admin_login.html", form=form)

        # Generate and send 2FA code
        code = ''.join(random.choices(string.digits, k=6))
        otp = OTPCode(user_id=user.id, code=code)
        db.session.add(otp)
        db.session.commit()

        send_email(
            user.email,
            "Rago Admin - Login Verification Code",
            f"Your one-time login code is: **{code}**\n\n"
            "This code expires in 10 minutes.\nDo not share it with anyone.\n\n"
            "If you did not request this, please secure your account immediately."
        )

        session['pending_user_id'] = user.id
        flash("A 6-digit verification code has been sent to your email.", "info")
        return redirect(url_for('verify_2fa'))

    return render_template("admin_login.html", form=form)


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_user_id' not in session:
        return redirect(url_for('admin_login'))

    user = User.query.get(session['pending_user_id'])
    if not user:
        session.pop('pending_user_id', None)
        return redirect(url_for('admin_login'))

    form = Verify2FAForm()

    if form.validate_on_submit():
        code = form.code.data.strip()
        print(f"[2FA DEBUG] Entered code: {code}")

        otp = OTPCode.query.filter_by(user_id=user.id, code=code, used=False)\
                          .order_by(OTPCode.created_at.desc()).first()

        if otp:
            age = datetime.utcnow() - otp.created_at
            print(f"[2FA DEBUG] Found OTP. Age: {age}, Used: {otp.used}")
            if age < timedelta(minutes=10):
                otp.used = True
                db.session.commit()
                login_user(user, remember=True)
                session.pop('pending_user_id', None)
                flash("Login successful.", "success")
                print("[2FA DEBUG] Login successful - redirecting to dashboard")
                return redirect(url_for('dashboard'))
            else:
                print("[2FA DEBUG] Code expired")
                flash("Invalid or expired code.", "danger")
        else:
            print("[2FA DEBUG] No matching unused OTP found")
            flash("Invalid or expired code.", "danger")

    return render_template("verify_2fa.html", form=form, email=user.email)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = ForgotPasswordForm()

    if form.validate_on_submit():
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
                f"Click here to reset your password:\n{reset_url}\n\n"
                "This link expires in 60 minutes.\nIf you did not request this, ignore this email."
            )

        flash("If an account exists with that email, a reset link has been sent.", "info")
        return redirect(url_for('admin_login'))

    return render_template("forgot_password.html", form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset = ResetToken.query.filter_by(token=token).first()
    if not reset or (datetime.utcnow() - reset.created_at) > timedelta(hours=1):
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        user = User.query.get(reset.user_id)
        user.set_password(form.password.data)
        db.session.delete(reset)
        db.session.commit()
        flash("Password reset successful. Please log in.", "success")
        return redirect(url_for('admin_login'))

    return render_template("reset_password.html", form=form, token=token)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('admin_login'))


@app.route('/dashboard')
@login_required
def dashboard():
    requests = POCRequest.query.order_by(POCRequest.created_at.desc()).all()
    return render_template("dashboard.html", requests=requests)


@app.route('/update_status/<int:id>', methods=['POST'])
@login_required
@role_required('admin', 'viewer')
def update_status(id):
    req = POCRequest.query.get_or_404(id)
    new_status = request.form.get("status")

    valid_statuses = ["Pending", "Approved", "Declined", "Completed", "Reviewed"]
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
        "Approved": "#28a745",
        "Completed": "#28a745",
        "Declined": "#dc3545",
        "Pending": "#ffc107",
        "Reviewed": "#6c757d"
    }.get(new_status, "#6c757d")

    # === CLIENT EMAIL – now type-specific ===
    client_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Your {req.request_type} Request Status Updated - Rago Global Solutions</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
        .container {{ max-width: 600px; margin: 30px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
        .header {{ background: {header_bg}; color: white; padding: 40px 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .content {{ padding: 40px 30px; color: #333; line-height: 1.7; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }}
        .btn {{ display: inline-block; background: {primary_btn}; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
        table {{ width: 100%; margin: 20px 0; border-collapse: collapse; }}
        td {{ padding: 10px 0; border-bottom: 1px solid #eee; }}
        .status-highlight {{ color: {status_color}; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Update: Your {req.request_type} Request Status</h1>
        </div>
        <div class="content">
            <p>Dear <strong>{req.contact_person}</strong>,</p>
            <p>We wanted to let you know that your {req.request_type.lower()} request with Rago Global Solutions has been reviewed and updated.</p>

            <h4 style="margin-top: 30px;">Status Details:</h4>
            <table>
                <tr><td><strong>Organization:</strong></td><td>{req.organization}</td></tr>
                <tr><td><strong>Contact Person:</strong></td><td>{req.contact_person}</td></tr>
                <tr><td><strong>Email:</strong></td><td>{req.email}</td></tr>
                <tr><td><strong>Phone:</strong></td><td>{req.phone or 'Not provided'}</td></tr>
                <tr><td><strong>Type:</strong></td><td>{req.request_type}</td></tr>
                <tr><td><strong>Status:</strong></td><td class="status-highlight">{new_status}</td></tr>
            </table>

            <p>{
                'Congratulations! Your ' + req.request_type.lower() + ' request has been approved. Our team will reach out shortly to confirm the next steps and schedule the session.' 
                if new_status == 'Approved' else
                'Unfortunately, your ' + req.request_type.lower() + ' request has been declined at this time. If you have any questions or would like to provide more details, feel free to reply to this email.' 
                if new_status == 'Declined' else
                'Your ' + req.request_type.lower() + ' session has been marked as completed. Thank you for working with us — we hope it was valuable!' 
                if new_status == 'Completed' else
                'Your ' + req.request_type.lower() + ' request is back in Pending status for further review. We\'ll update you soon.' 
                if new_status == 'Pending' else
                'We have reviewed and updated your ' + req.request_type.lower() + ' request status. We\'ll keep you informed of any next steps.'
            }</p>

            <p style="margin-top: 30px; text-align: center;">
                <a href="https://rago-tech.vercel.app" class="btn">Visit Our Website</a>
            </p>

            <p>If you have any questions or need further assistance, please reply directly to this email.</p>

            <p>Best regards,<br>
            <strong>Rago Global Solutions Team</strong><br>
            <a href="mailto:helpdesk.ragosa.tech@gmail.com">helpdesk.ragosa.tech@gmail.com</a><br>
            +234 813 887 9938</p>
        </div>
        <div class="footer">
            © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
            Built with passion in Lagos, Nigeria
        </div>
    </div>
</body>
</html>
"""

    client_plain = (
        f"Dear {req.contact_person},\n\n"
        f"Your {req.request_type} request for {req.organization} has been updated to: {new_status}\n\n"
        "We will reach out with next steps if approved.\n\n"
        "Best regards,\nRago Global Solutions"
    )

    # === ADMIN NOTIFICATION (also type-specific) ===
    admin_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{req.request_type} Request Status Updated - Rago Admin</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
        .container {{ max-width: 600px; margin: 30px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
        .header {{ background: {header_bg}; color: white; padding: 40px 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .content {{ padding: 40px 30px; color: #333; line-height: 1.7; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }}
        table {{ width: 100%; margin: 20px 0; border-collapse: collapse; }}
        td {{ padding: 10px 0; border-bottom: 1px solid #eee; }}
        .btn {{ display: inline-block; background: {primary_btn}; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
        .status {{ color: {status_color}; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{req.request_type} Request Status Updated</h1>
        </div>
        <div class="content">
            <p>Hello Admin,</p>
            <p>A {req.request_type.lower()} request has just been updated in the system.</p>

            <h4 style="margin-top: 30px;">Update Details:</h4>
            <table>
                <tr><td><strong>Type:</strong></td><td>{req.request_type}</td></tr>
                <tr><td><strong>Organization:</strong></td><td>{req.organization}</td></tr>
                <tr><td><strong>Contact Person:</strong></td><td>{req.contact_person}</td></tr>
                <tr><td><strong>Email:</strong></td><td>{req.email}</td></tr>
                <tr><td><strong>Phone:</strong></td><td>{req.phone or 'Not provided'}</td></tr>
                <tr><td><strong>Status Changed To:</strong></td><td class="status">{new_status}</td></tr>
                <tr><td><strong>Updated By:</strong></td><td>{current_user.username}</td></tr>
            </table>

            <p style="margin-top: 30px; text-align: center;">
                <a href="{url_for('dashboard', _external=True)}" class="btn">View in Dashboard</a>
            </p>

            <p>Please review if further action is needed.</p>

            <p>Best regards,<br>
            <strong>Rago Admin System</strong></p>
        </div>
        <div class="footer">
            © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
            Built with passion in Lagos, Nigeria
        </div>
    </div>
</body>
</html>
"""

    admin_plain = (
        f"{req.request_type} request status updated:\n\n"
        f"Organization: {req.organization}\n"
        f"Contact: {req.contact_person} ({req.email})\n"
        f"New status: {new_status}\n"
        f"Updated by: {current_user.username}\n\n"
        f"Dashboard: {url_for('dashboard', _external=True)}"
    )

    # Send notifications
    send_email(
        req.email,
        f"Your {req.request_type} Request Status Updated - {new_status}",
        plain_body=client_plain,
        html_body=client_html
    )

    send_email(
        "helpdesk.ragosa.tech@gmail.com",
        f"[ADMIN] {req.request_type} Request Status Updated - {new_status}",
        plain_body=admin_plain,
        html_body=admin_html
    )

    flash(f"Status updated to {new_status}. Client and admin notified.", "success")
    return redirect(url_for('dashboard'))

UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

from secrets import token_urlsafe  # for secure token generation

@app.route('/request-demo', methods=['GET', 'POST'])
def request_demo():
    form = PublicDemoForm()

    if form.validate_on_submit():
        # === Prepare form data ===
        form_data = {
            'organization': form.organization.data,
            'contact_person': form.contact_person.data,
            'email': form.email.data.strip().lower(),
            'phone': form.phone.data,
            'description': form.description.data,
            'request_type': form.request_type.data,
            'scheduled_date': form.scheduled_date.data.isoformat() if form.scheduled_date.data else None,
            'attachment_filename': None,  # handle attachment separately below
        }

        # === Handle attachment ===
        attachment_path = None
        if form.attachment.data and form.request_type.data == 'POC':
            filename = secure_filename(form.attachment.data.filename)
            attachment_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            form.attachment.data.save(attachment_path)
            form_data['attachment_filename'] = filename
            form_data['attachment_path'] = attachment_path  # temporary, for later use

        # === Generate verification token ===
        token = token_urlsafe(32)
        verification = RequestVerificationToken(
            token=token,
            email=form_data['email'],
            form_data=form_data
        )
        db.session.add(verification)
        db.session.commit()

        # === Send verification email ===
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
                .btn {{ display: inline-block; background: #007BFF; color: white; padding: 14px 40px; text-decoration: none; border-radius: 6px; font-size: 18px; margin: 20px 0; }}
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
                    
                    <p>If the button doesn't work, copy and paste this link into your browser:</p>
                    <p><a href="{verify_url}">{verify_url}</a></p>
                    
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

    if not verification or (datetime.utcnow() - verification.created_at) > timedelta(hours=0.17):
        flash("This verification link is invalid or has expired. Please submit your request again.", "danger")
        return redirect(url_for('request_demo'))

    form_data = verification.form_data

    # === Handle attachment ===
    attachment_filename = form_data.get('attachment_filename')
    attachment_path = form_data.get('attachment_path')

    # === Find if this is an update (match email + org) ===
    existing_req = POCRequest.query.filter(
        POCRequest.email == form_data['email'],
        POCRequest.organization == form_data['organization'],
        POCRequest.status.in_(["Pending", "Approved", "Scheduled"])
    ).order_by(POCRequest.created_at.desc()).first()

    if existing_req:
        # UPDATE existing
        existing_req.organization = form_data['organization']
        existing_req.contact_person = form_data['contact_person']
        existing_req.email = form_data['email']
        existing_req.phone = form_data['phone']
        existing_req.description = form_data['description']
        existing_req.request_type = form_data['request_type']
        existing_req.scheduled_date = datetime.fromisoformat(form_data['scheduled_date']) if form_data.get('scheduled_date') else None
        if attachment_filename:
            existing_req.attachment = attachment_filename
        if existing_req.status in ["Scheduled", "Completed"]:
            existing_req.status = "Pending"
        db.session.commit()
        used_request = existing_req
        is_update = True
    else:
        # CREATE new
        new_request = POCRequest(
            organization=form_data['organization'],
            contact_person=form_data['contact_person'],
            email=form_data['email'],
            phone=form_data['phone'],
            description=form_data['description'],
            request_type=form_data['request_type'],
            scheduled_date=datetime.fromisoformat(form_data['scheduled_date']) if form_data.get('scheduled_date') else None,
            attachment=attachment_filename,
            status="Pending"
        )
        db.session.add(new_request)
        db.session.commit()
        used_request = new_request
        is_update = False

    # Mark token as used
    verification.used = True
    db.session.commit()

    # === Send final emails ===
    type_lower = used_request.request_type.lower()
    is_enquiry = used_request.request_type == 'Enquiry'
    action_word = "updated" if is_update else "received"
    time_label = "Preferred Contact Time" if is_enquiry else "Preferred Date & Time"

    # Admin email with full description
    admin_subject = f"{used_request.request_type} {action_word.capitalize()} (Verified)"
    desc_preview = used_request.description[:800] + "..." if len(used_request.description) > 800 else used_request.description

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
            .desc-box {{ background: #f8f9fa; padding: 15px; border-left: 4px solid #007BFF; margin: 20px 0; white-space: pre-wrap; word-wrap: break-word; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>{admin_subject}</h1>
            </div>
            <div class="content">
                <p>A {type_lower} request has been {action_word} and email verified.</p>
                <table>
                    <tr><td><strong>ID:</strong></td><td>{used_request.id}</td></tr>
                    <tr><td><strong>Type:</strong></td><td>{used_request.request_type}</td></tr>
                    <tr><td><strong>Organization:</strong></td><td>{used_request.organization}</td></tr>
                    <tr><td><strong>Contact Person:</strong></td><td>{used_request.contact_person}</td></tr>
                    <tr><td><strong>Email:</strong></td><td>{used_request.email}</td></tr>
                    <tr><td><strong>Phone:</strong></td><td>{used_request.phone or 'Not provided'}</td></tr>
                    <tr><td><strong>{time_label}:</strong></td><td>{used_request.scheduled_date.strftime('%A, %d %B %Y at %H:%M') if used_request.scheduled_date else 'Not specified'}</td></tr>
                    <tr><td><strong>Attachment:</strong></td><td>{used_request.attachment or 'None'}</td></tr>
                </table>

                <h4 style="margin-top: 25px;">User's Message / Description:</h4>
                <div class="desc-box">
                    {desc_preview}
                </div>

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
        plain_body=f"{used_request.request_type} {action_word} from {used_request.organization}\n\nDescription:\n{used_request.description}",
        html_body=admin_html,
        attachment_path=attachment_path if attachment_path and os.path.exists(attachment_path) else None
    )

    # Client confirmation email
    client_greeting = "Thank you for following up!" if is_update else ("Thank you for reaching out!" if is_enquiry else f"Thank you for your interest in Rago Global Solutions!")
    client_body_intro = f"Your {type_lower} request has been {action_word} and verified."
    client_body_next = "Our team has received your message and will get back to you soon." if is_enquiry else "Our team will review your request and get back to you within 24–48 hours."

    client_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Your {used_request.request_type} Confirmed - Rago Global</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
            .container {{ max-width: 600px; margin: 30px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
            .header {{ background: #001f3f; color: white; padding: 40px 30px; text-align: center; }}
            .header h1 {{ margin: 0; font-size: 28px; }}
            .content {{ padding: 40px 30px; color: #333; line-height: 1.7; }}
            .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }}
            .btn {{ display: inline-block; background: #007BFF; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Your {used_request.request_type} Confirmed!</h1>
            </div>
            <div class="content">
                <p>Dear <strong>{used_request.contact_person}</strong>,</p>
                <p>{client_greeting}</p>
                <p>{client_body_intro}</p>
                
                <h4 style="margin-top: 30px;">Your Submission Details:</h4>
                <table>
                    <tr><td><strong>Organization:</strong></td><td>{used_request.organization}</td></tr>
                    <tr><td><strong>Contact Person:</strong></td><td>{used_request.contact_person}</td></tr>
                    <tr><td><strong>Email:</strong></td><td>{used_request.email}</td></tr>
                    <tr><td><strong>Phone:</strong></td><td>{used_request.phone or 'Not provided'}</td></tr>
                    <tr><td><strong>{time_label}:</strong></td><td>{used_request.scheduled_date.strftime('%A, %d %B %Y at %H:%M') if used_request.scheduled_date else 'Not specified'}</td></tr>
                    <tr><td><strong>Attachment:</strong></td><td>{used_request.attachment or 'None'}</td></tr>
                </table>

                <p>{client_body_next}</p>

                <p style="margin-top: 30px;">
                    <a href="https://rago-tech.vercel.app" class="btn">Visit Our Website</a>
                </p>

                <p>Best regards,<br>
                <strong>Rago Global Solutions Team</strong><br>
                <a href="mailto:helpdesk.ragosa.tech@gmail.com">helpdesk.ragosa.tech@gmail.com</a><br>
                +234 813 887 9938</p>
            </div>
            <div class="footer">
                © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
                Built with passion in Lagos, Nigeria
            </div>
        </div>
    </body>
    </html>
    """

    send_email(
        used_request.email,
        f"Your {used_request.request_type} Confirmed - Rago Global Solutions",
        plain_body=f"Your request has been verified and received. We'll be in touch soon.",
        html_body=client_html
    )

    flash("Thank you! Your email has been verified and your request has been successfully submitted.", "success")
    return redirect(url_for('home'))

@app.route('/schedule/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'viewer')
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

        # Customized HTML email – type-specific + attachment info
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Your {req.request_type} Scheduled - Rago Global Solutions</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f6f9fc; }}
                .container {{ max-width: 600px; margin: 30px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
                .header {{ background: #001f3f; color: white; padding: 40px 30px; text-align: center; }}
                .header h1 {{ margin: 0; font-size: 28px; }}
                .content {{ padding: 40px 30px; color: #333; line-height: 1.7; }}
                .footer {{ background: #f8f9fa; padding: 20px; text-align: center; font-size: 14px; color: #666; }}
                .btn {{ display: inline-block; background: #007BFF; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin-top: 20px; }}
                table {{ width: 100%; margin: 20px 0; border-collapse: collapse; }}
                td {{ padding: 10px 0; border-bottom: 1px solid #eee; }}
                .highlight {{ color: #007BFF; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Your {req.request_type} is Confirmed!</h1>
                </div>
                <div class="content">
                    <p>Dear <strong>{req.contact_person}</strong>,</p>
                    <p>Great news! Your requested {req.request_type.lower()} with Rago Global Solutions has been officially scheduled.</p>

                    <h4 style="margin-top: 30px;">Scheduled Details:</h4>
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

                    <!-- Conditional text about attachment moved to template -->
                    <p>We’re looking forward to { 
                        'showing you the platform and answering all your questions' 
                        if req.request_type == 'Demo' else
                        'working through the proof of concept together' 
                        if req.request_type == 'POC' else
                        'discussing your enquiry in detail'
                    }!</p>

                    <p style="margin-top: 30px; text-align: center;">
                        <a href="https://rago-tech.vercel.app" class="btn">Visit Our Website</a>
                    </p>

                    <p>If you need to reschedule or have any questions before the {req.request_type.lower()}, feel free to reply to this email.</p>

                    <p>Best regards,<br>
                    <strong>Rago Global Solutions Team</strong><br>
                    <a href="mailto:helpdesk.ragosa.tech@gmail.com">helpdesk.ragosa.tech@gmail.com</a><br>
                    +234 813 887 9938</p>
                </div>
                <div class="footer">
                    © 2026 Rago Global Solutions Ltd. All rights reserved.<br>
                    Built with passion in Lagos, Nigeria
                </div>
            </div>
        </body>
        </html>
        """
        plain_body = (
            f"Dear {req.contact_person},\n\n"
            f"Your {req.request_type} is now scheduled for:\n"
            f"📅 {req.scheduled_date.strftime('%A, %d %B %Y at %H:%M')}\n\n"
            f"Attachment: {attachment_filename or 'None'}\n"
            "Calendar invite attached.\n"
            f"We look forward to the {req.request_type.lower()}!\n\n"
            "Best regards,\nRago Global Solutions"
        )

        send_email(
            req.email,
            f"Your {req.request_type} Scheduled – Rago Global Solutions",
            plain_body=plain_body,
            html_body=html_body,
            attachment_path=ics_path,
            # Attach admin-uploaded file too (if any)
            extra_attachment=attachment_path
        )

        flash(f"{req.request_type} scheduled and notification sent to client successfully.", "success")
        return redirect(url_for('dashboard'))

    return render_template("schedule.html", form=form, request=req)

@app.route('/admin/users')
@login_required
@role_required('admin')
def manage_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_user():
    form = CreateUserForm()

    if form.validate_on_submit():
        new_user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            role=form.role.data.strip()
        )
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash(f"User '{new_user.username}' created successfully.", "success")
        return redirect(url_for('manage_users'))

    return render_template('admin_user_form.html', form=form, title="Create New User")


@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot edit your own account from here.", "warning")
        return redirect(url_for('manage_users'))

    form = EditUserForm()
    # Pre-fill form
    if request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        form.role.data = user.role

    if form.validate_on_submit():
        user.username = form.username.data.strip()
        user.email = form.email.data.strip().lower()
        user.role = form.role.data.strip()
        if form.password.data:
            user.set_password(form.password.data)
        db.session.commit()
        flash(f"User '{user.username}' updated successfully.", "success")
        return redirect(url_for('manage_users'))

    return render_template('admin_user_form.html', form=form, title="Edit User", user=user)


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for('manage_users'))

    db.session.delete(user)
    db.session.commit()
    flash(f"User '{user.username}' deleted.", "success")
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
            admin.set_password(os.getenv("ADMIN_PASSWORD", "ChangeMeSecure123!"))
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