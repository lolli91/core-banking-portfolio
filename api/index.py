from flask import Flask, render_template, request, flash, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from email_validator import validate_email, EmailNotValidError
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-super-secret-key-change-this-in-production'  # Change this!

# Email configuration - Use Gmail App Password (recommended)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'helpdesk.ragosa.tech@gmail.com'  # Your email
app.config['MAIL_PASSWORD'] = 'xwjr cwcq bsye qxhj'                # Gmail App Password (NOT regular password)
app.config['MAIL_DEFAULT_SENDER'] = 'helpdesk.ragosa.tech@gmail.com'

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    company = StringField('Company Name (Optional)', validators=[Length(max=150)])  # New field
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[Length(max=20)])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=10, max=1000)])
    submit = SubmitField('Send Message')

def send_email(name, company, email, phone, message):
    """Send contact form email"""
    subject = f"New Contact Form Submission from {name}"
    body = f"""
    New message from your Core Banking Portfolio website:

    Name: {name}
    Company: {company or 'Not provided'}
    Email: {email}
    Phone: {phone or 'Not provided'}
    
    Message:
    {message}
    """

    msg = MIMEMultipart()
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = app.config['MAIL_USERNAME']
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.sendmail(app.config['MAIL_USERNAME'], app.config['MAIL_USERNAME'], msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

@app.route('/', methods=['GET', 'POST'])
def home():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        company = form.company.data
        email = form.email.data
        phone = form.phone.data
        message = form.message.data

        if send_email(name, company, email, phone, message):
            flash('Thank you! Your message has been sent successfully. You will get a feedback soon.', 'success')
        else:
            flash('Sorry, there was an error sending your message. Please try again or email me directly.', 'danger')
        
        return redirect(url_for('home') + '#contact')

    return render_template('index.html', form=form)

if __name__ == "__main__":
    app.run(debug=True)