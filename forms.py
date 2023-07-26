from wtforms import Form, StringField, PasswordField, EmailField, DateField, validators, IntegerField, RadioField, TextAreaField, FileField, SelectField
from flask_wtf import FlaskForm, RecaptchaField

class create_post(Form):
    title = StringField('Caption', [validators.length(min=1, max=50), validators.DataRequired()])
    body = TextAreaField('Body', [validators.length(max=5000)])
    category = SelectField('Category', choices=['placeholder choice', 'another placeholder choice'], validators=[validators.DataRequired()])

class create_comment(Form):
    body = TextAreaField('', render_kw={'placeholder': 'Add a comment:'})

class signup_form(Form):
    username = StringField('Username', validators=[validators.regexp('^[A-za-z1-9]+$', message='Username should not contain symbols.'), validators.DataRequired()]) # Regex to allow only string
    email = StringField('School Email', validators=[validators.DataRequired(), validators.regexp('^[a-zA-Z0-9]+@mymail\.nyp\.edu\.sg$', message='Must be a valid xxxxxxx@mymail.nyp.edu.sg')])
    password = PasswordField('Password', validators=[validators.DataRequired(), validators.regexp('^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[\W_]).{8,64}$', message='Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character. It should be between 8 and 64 characters in length.')])
    recaptcha = RecaptchaField()

class login_form(Form):
    username = StringField('Username', validators=[validators.regexp('^[A-za-z1-9]+$', message='Username should not contain symbols.'), validators.DataRequired()]) # Regex to allow only string
    password = PasswordField('Password', validators=[validators.DataRequired()])

class security_questions(Form):
    qn1 = SelectField('First Security Question', choices=['What was your primary school?', 'What is your favourite childhood movie?', 'What is your favorite colour?'], validators=[validators.DataRequired()])
    qn1_ans = StringField('First Security Question Answer', validators=[validators.DataRequired()])
    qn2 = SelectField('Second Security Question', choices=["What is your mother's maiden name?", "What is your father's first job?", "What is your first job?"], validators=[validators.DataRequired()])
    qn2_ans = StringField('Second Security Question Answer', validators=[validators.DataRequired()])
