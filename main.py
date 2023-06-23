from flask import Flask, render_template, request, redirect, url_for, session, app
from forms import *

app = Flask(__name__)




@app.route('/signup', methods=['GET', 'POST'])
def signup():

    # If there's a POST request(Form submitted) enter statement.
    if request.method == 'POST':
        #Try:
            # Retrieve User Credential in the form

            # Hash the password

            # DML into MySQLdb
        pass


@app.route('/login', methods=['GET', 'POST'])
def signup():

    # If there's a POST request(Form submitted) enter statement.
    if request.method == 'POST':
        #Try:
            # Retrieve User Credential in the form

            # Retrieve account from sql (hash pass)
            # if successful
                #set session


        pass


@app.route('/createpost', methods=['GET', 'POST'])
def createpost():
    
    form = createpost(request.form)
    if request.method == 'POST' and form.validate():
        #assign form data to variables
        title = form.title.data
        body = form.body.data
        if form.attachment.data:
            attachment = form.attachment.data
        category = form.category.data

        #add form data to database
        #code here
        print("post added to database, redirecting to homepage")
        return redirect(url_for('index'))
    
    
    return render_template('createpost.html', form=form)

        


if __name__ == '__main__':
    app.run()
