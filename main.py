from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import MySQLdb.cursors
from mysql.connector import Error
from datetime import date, timedelta
from forms import *

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=5)

# Config the Setting
app.config['SECRET_KEY'] = 'helpmyasshurt'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Hasooni0305!'
app.config['MYSQL_DB'] = 'connectnypian_db'  # Standardised schema name
app.config['MYSQL_PORT'] = 3306

#Intialize MYSQL
mysql = MySQL(app)

#Common MYSQL code
# mycursor.execute('SELECT * FROM %s', (table)) # Execute a query
# account = mycursor.fetchone #Fetch one record


bcrypt = Bcrypt() #Creating a bcrypt class to use hashing function

# MYSQL CHEAT CODE - Created by ur handsome daddy
def connection_cursor(): #This function allow you to obtan the cursor
    return mysql.connection.cursor(MySQLdb.cursors.DictCursor)
def cursor_close(cursor): #This function close the cursor that you obtained
    cursor.close()
def connection_commit(): #This function commit the query
    mysql.connection.commit()
def connection_close(): #This function close the connection
    mysql.connection.close()

def execute_commit(query, parameterized_query_data=None): #Get cursor, execute and return result
    try:
        cursor = connection_cursor()
        cursor.execute(query, parameterized_query_data)
        connection_commit()
        cursor_close(cursor)
    except Error as e:
        print("Error Executing query:", e)
        return None

def execute_fetchone(query, parameterized_query_data=None): #Get cursor, execute and return result
    try:
        cursor = connection_cursor()
        cursor.execute(query, parameterized_query_data)
        result = cursor.fetchone()
        cursor_close(cursor)
        return result
    except Error as e:
        print("Error Executing query:", e)
        return None

def execute_fetchall(query, parameterized_query_data=None): #Get cursor, execute and return result
    try:
        cursor = connection_cursor()
        cursor.execute(query, parameterized_query_data)
        result = cursor.fetchall()
        cursor_close(cursor)
        return result
    except Error as e:
        print("Error Executing query:", e)
        return None

# END OF CHEAT CODE

# Session module
def create_session(session_key, value):
    try:
        session[session_key] = value
    except Error as e:
        print("An error occurred while creating session.\n", e)

def remove_session(session_key):
    try:
        session.pop(session_key, None)
    except Error as e:
        print("An error occurred while popping session.\n", e)

def check_session(session_key):
    try:
        if session_key in session:
            return True
        else:
            return False
    except Error as e:
        print("An unknown error occurred while checking session.\n", e)

def check_login_status():
    try:
        login_status = check_session('login_status')
    except Error as e:
        print("Unknown error when checking login status session", e)
    else:
        return login_status

# End of session function


# function for creating a comment, must assign createcomment form to a variable in applicable routes
def createcomment(form, post_id):
    try:
        if request.method == 'POST':
            body = form.body.data

            sql = "INSERT INTO comments (body, account_id, post_id) VALUES (%s, %s, %s)"
            val = (body, session['login_id'], post_id)
            execute_commit(sql, val)

            print("comment added to database")

    except Error as e:
        print('Error creating comment: ', e)


def createlike(post_id):
    try:
        if 'id' in session:
            sql = "INSERT INTO like (like_date, account_id) VALUES (%s, %s)"
            val = (post_id, session['login_id'])
            execute_commit(sql, val)

    except Error as e:
        print("Error creating like: ", e)


# END OF EXTERNAL FUNCTIONS
@app.route('/')
def home():
    # Extract all the post from sql
    login_status = check_login_status() #Check for login status

    if login_status:
        print("logged in")
        return render_template('index.html')
    else:
        return redirect(url_for('signup'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'login_status' in session:
        return redirect(url_for('home'))
    
    form = signup_form(request.form)
    # If there's a POST request(Form submitted) enter statement.
    if request.method == 'POST':
        # Try:
        # Retrieve User Credential in the form
        try:
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
        except Error as e:
            print("Error trying to retrieve sign up for credential\n", e)
        else:
            hashed_password = bcrypt.generate_password_hash(password) # Hash the password

            if hashed_password:
                # Inserting data into account: account_id, email, username, date_created
                execute_commit('INSERT INTO accounts (hashed_pass, school_email, username) VALUES (%s, %s, %s)',(hashed_password, email, username))
                print("Account created")
                return redirect(url_for('login'))

        # DML into MySQLdb
    return render_template('processes/signup.html', form=form)



@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'login_status' in session:
        return redirect(url_for('home'))
    
    form=login_form(request.form)
    # If there's a POST request(Form submitted) enter statement.
    if request.method == 'POST': # If a form is submitted
        try:
            # Retrieve User Credential in the form
            username = request.form['username']
            password = request.form['password']
            result = execute_fetchone('SELECT * FROM accounts WHERE username = %s', (username,)) # Getting data from database
            #Assigning value from the data retrieved
            hashed_pass = result['hashed_pass']
            account_id = result['account_id']
            username = result['username']
        except Error as e:
            print("Unknown error occurred while retrieving user credential.\n", e)
        else:
            #If able to retrieve, continue
            # Checking if the there's a result from the sql query and checking the value of both hash function
            if result and bcrypt.check_password_hash(hashed_pass, password):
                try:
                    #If login success, try to create session for the user
                    create_session('login_status', True)
                    create_session('login_id', account_id)
                    create_session('username', username)
                except Error as e: #If login fail
                    print("Login Fail")
                    print("Unknown error occurred while trying to create session for user.\n", e)
                else:
                    print("Login success")
                    return redirect(url_for('home'))

    return render_template('processes/login.html', form=form)

@app.route('/logout')
def logout():
    remove_session('login_status')
    remove_session('login_id')
    remove_session('username')
    return redirect(url_for('home'))




@app.route('/createpost', methods=['GET', 'POST'])
def createpost():
    form = create_post(request.form)
    if request.method == 'POST' and form.validate():
        # assign form data to variables
        title = form.title.data
        body = form.body.data
        category = form.category.data

        # add form data to database
        sql = "INSERT INTO posts (title, body, category, account_id) VALUES (%s, %s, %s, %s)"
        val = (title, body, category, session['login_id'])
        execute_commit(sql, val)
        print("post added to database, redirecting to homepage")
        return redirect(url_for('home'))

    return render_template('/processes/createpost.html', form=form)



if __name__ == '__main__':
    app.run(debug=True)
