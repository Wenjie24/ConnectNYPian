from wtforms import Form, StringField, PasswordField, EmailField, DateField, validators, IntegerField, RadioField, TextAreaField, FileField, SelectField

class createpost(Form):
    title = StringField('Caption', [validators.length(min=1, max=50), validators.DataRequired()])
    body = TextAreaField('Body', [validators.length(max=5000)])
    category = SelectField('Category', choices=['add stuff later i guess'], validators=[validators.DataRequired()])

class createcomment(Form):
    body = TextAreaField('', render_kw={'placeholder': 'Add a comment:'})

class signup(Form):
    username = StringField('Username', validators=[validators.regexp('^[A-za-z]+$'), validators.DataRequired()]) # Regex to allow only string
    email = StringField('School Email', validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])

class login(Form):
    username = StringField('Username', validators=[validators.regexp('^[A-za-z]+$'), validators.DataRequired()]) # Regex to allow only string
    password = PasswordField('Password', validators=[validators.DataRequired()])
