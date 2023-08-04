from wtforms import Form, StringField, PasswordField, EmailField, DateField, validators, IntegerField, RadioField, TextAreaField, FileField, SelectField
from flask_wtf import FlaskForm, RecaptchaField

class create_post(Form):
    title = StringField('', [validators.length(min=1, max=50), validators.DataRequired()], render_kw={'placeholder': 'Title:'})
    body = TextAreaField('', [validators.length(max=5000)], render_kw={'style': 'height:200px', 'placeholder': 'Body:'})
    category = SelectField('', choices=['placeholder choice', 'another placeholder choice'], validators=[validators.DataRequired()], render_kw={'style':'height:45px'})

class create_comment(Form):
    body = TextAreaField('', render_kw={'placeholder': 'Comment:'}, validators=[validators.DataRequired()])

class signup_form(Form):
    username = StringField('Username', validators=[validators.regexp('^[A-za-z1-9]+$', message='Username should not contain symbols.'), validators.DataRequired()]) # Regex to allow only string
    email = StringField('School Email', validators=[validators.DataRequired(), validators.regexp('^[a-zA-Z0-9]+@mymail\.nyp\.edu\.sg$', message='Must be a valid xxxxxxx@mymail.nyp.edu.sg')])
    school = SelectField('School', choices=['School of Applied Science (SAS)', 'School of Business Management (SBM)', 'School of Engineering (SoE)', 'School of Health and Social Sciences (SHSS)', 'School Of Information Technology (SIT)'], validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired(), validators.regexp('^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[\W_]).{8,64}$', message='Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character. It should be between 8 and 64 characters in length.')])
    recaptcha = RecaptchaField()

class login_form(Form):
    username = StringField('Username', validators=[validators.regexp('^[A-za-z1-9]+$', message='Username should not contain symbols.'), validators.DataRequired()]) # Regex to allow only string
    password = PasswordField('Password', validators=[validators.DataRequired()])

class security_questions(Form):
    qn1 = SelectField('First Security Question:', choices=['What was your primary school?', 'What is your favourite childhood movie?', 'What is your favorite colour?'], validators=[validators.DataRequired()])
    qn1_ans = StringField('Answer', validators=[validators.DataRequired()])
    qn2 = SelectField('Second Security Question:', choices=["What is your mother's maiden name?", "What is your father's first job?", "What is your first job?"], validators=[validators.DataRequired()])
    qn2_ans = StringField('Answer', validators=[validators.DataRequired()])

class report_form(Form):
    reason = SelectField('Reason for reporting:', choices=['Offensive content', 'Spam', "I'm being impersonated", 'Sensitive or disturbing content'], validators=[validators.DataRequired()])

class reset_pass_form(Form):
    password = PasswordField('Password', validators=[validators.DataRequired(), validators.regexp('^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[\W_]).{8,64}$', message='Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character. It should be between 8 and 64 characters in length.')])
