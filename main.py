from flask import Flask, render_template, request, redirect, url_for, session, app

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




if __name__ == '__main__':
    app.run()
