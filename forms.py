from wtforms import Form, StringField, PasswordField, EmailField, DateField, validators, IntegerField, RadioField, TextAreaField, FileField, SelectField
from flask_wtf import FlaskForm, RecaptchaField

class create_post(Form):
    title = StringField('Caption', [validators.length(min=1, max=50), validators.DataRequired()])
    body = TextAreaField('Body', [validators.length(max=5000)])
    category = SelectField('Category', choices=['placeholder choice', 'another placeholder choice'], validators=[validators.DataRequired()])

class create_comment(Form):
    body = TextAreaField('', render_kw={'placeholder': 'Add a comment:'})

class signup_form(Form):
    username = StringField('Username', validators=[validators.regexp('^[A-za-z1-9]+$'), validators.DataRequired()]) # Regex to allow only string
    email = StringField('School Email', validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired(), validators.regexp('^[A-za-z1-9]+$'), validators.length(min=8, max=64)])
    recaptcha = RecaptchaField()


class login_form(Form):
    username = StringField('Username', validators=[validators.regexp('^[A-za-z]+$'), validators.DataRequired()]) # Regex to allow only string
    password = PasswordField('Password', validators=[validators.DataRequired(), validators.regexp('^[A-za-z1-9]+$')])
