from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import MySQLdb.cursors
from mysql.connector import Error
from datetime import date, timedelta
from forms import *

app = Flask(__name__)

# Config the Setting
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'wenjie'
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

def execute_commit(query): #Get cursor, execute and return result
    try:
        cursor = connection_cursor()
        cursor.execute(query)
        connection_commit()
        cursor_close(cursor)
    except Error as e:
        print("Error Executing query:", e)
        return None

def execute_fetchone(query): #Get cursor, execute and return result
    try:
        cursor = connection_cursor()
        cursor.execute(query)
        result = cursor.fetchone()
        cursor_close(cursor)
        return result
    except Error as e:
        print("Error Executing query:", e)
        return None

def execute_fetchall(query): #Get cursor, execute and return result
    try:
        cursor = connection_cursor()
        cursor.execute(query)
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


# End of session function


# function for creating a comment, must assign createcomment form to a variable in applicable routes
def createcomment(form, post_id):
    try:
        if request.method == 'POST':
            body = form.body.data
            comment_date = date.today

            sql = "INSERT INTO comments (body, comment_date, account_id, post_id) VALUES (%s, %s, %s, %s)"
            val = (body, comment_date, session['id'], post_id)
            execute_fetchall(sql, val)
            connection_commit()
            
            print("comment added to database")

    except Error as e:
        print('Error creating comment: ', e)


def createlike(post_id):
    try:
        if 'id' in session:
            like_date = date.today
            sql = "INSERT INTO like (like_date, post_id, account_id) VALUES (%s, %s, %s)"
            val = (like_date, post_id, session['id'])
            execute_fetchall(sql, val)
            connection_commit()

    except Error as e:
        print("Error creating like: ", e)


# END OF EXTERNAL FUNCTIONS
@app.route('/')
def home():
    return 'home'


@app.route('/signup', methods=['GET', 'POST'])
def signup():
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
                execute_commit('INSERT INTO accounts VALUES (null, %s, %s, %s, null)',(email, username, hashed_password))



        # DML into MySQLdb
    return 'sign up page'


@app.route('/login', methods=['GET', 'POST'])
def login():
    # If there's a POST request(Form submitted) enter statement.
    if request.method == 'POST':
        # Try:
        # Retrieve User Credential in the form
        try:
            username = request.form['username']
            password = request.form['password']
            result = execute_fetchone('SELECT username FROM accounts WHERE username = %s', (username,))
            hashed_pass = result['password']
            account_id = result['id']
            username = result['username']
        except Error as e:
            print("Unknown error occurred while retrieving user credential.\n", e)
        else:
            #If able to retrieve, continue
            # Checking if the there's a result from the sql query and checking the value of both hash function
            if result and bcrypt.check_password_hash(hashed_pass, password):
                try:
                    create_session('login_status', True)
                    create_session('login_id', account_id)
                    create_session('username', username)
                except Error as e:
                    print("Unknown error occurred while trying to create session for user.\n", e)
                else:
                    redirect(url_for(home))



    return 'Login page'





@app.route('/createpost', methods=['GET', 'POST'])
def createpost():
    form = createpost(request.form)
    if request.method == 'POST' and form.validate():
        # assign form data to variables
        title = form.title.data
        body = form.body.data
        date = date.today()
        category = form.category.data

        # add form data to database
        sql = "INSERT INTO posts (title, body, publish_time, category, account_id) VALUES (%s, %s, %s, %s, %s)"
        val = (title, body, date, category, session['id'])
        execute_fetchall(sql, val)
        connection_commit()
        print("post added to database, redirecting to homepage")
        return redirect(url_for('index'))

    return render_template('/processes/createpost.html', form=form)



if __name__ == '__main__':
    app.run(debug=True)
