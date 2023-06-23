from wtforms import Form, StringField, PasswordField, EmailField, DateField, validators, IntegerField, RadioField, TextAreaField, FileField, SelectField

class createpost(Form):
    title = StringField('Caption', [validators.length(min=1, max=50), validators.DataRequired()])
    body = StringField('Body', [validators.length(max=5000)])
    attachment = FileField('Attachment')
    category = SelectField('Category', choices=['add stuff later i guess'], validators=validators.DataRequired())