from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from flask_mysqldb import MySQL
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


# MYSQL CHEAT CODE - Created by ur handsome daddy
def connection_cursor(): #This function allow you to obtan the cursor
    return mysql.connection.cursor(MySQLdb.cursors.DictCursor)
def cursor_close(cursor): #This function close the cursor that you obtained
    cursor.close()
def connection_commit(): #This function commit the query
    mysql.connection.commit()
def connection_close(): #This function close the connection
    mysql.connection.close()

def execute_fetchone(query): #Get cursor, execute and close
    try:
        cursor = connection_cursor()
        cursor.execute(query)
        result = cursor.fetchone()
        cursor_close(cursor)
        return result
    except Error as e:
        print("Error Executing query:", e)
        return None

def execute_fetchall(query): #Get cursor, execute and close
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


# function for creating a comment, must assign createcomment form to a variable in applicable routes
def createcomment(form):
    if request.method == 'POST':
        body = form.body.data


        sql = "INSERT INTO comments (body) VALUES (%s)"
        val = (body)
        mycursor = obtain_cursor() # To activate a cursor
        mycursor.execute(sql, val)
        mysql.connection.commit()
        close_cursor(mycursor)
        print("comment added to database")

    pass


def createlike(post_id):
    if 'id' in session:
        like_date = date.today
        sql = "INSERT INTO like (like_date, post_id, account_id) VALUES (%s, %s, %s)"
        val = (like_date, post_id, session[id])
        mycursor = obtain_cursor()
        mycursor.execute(sql, val)
        mydb.commit()

    pass


# END OF EXTERNAL FUNCTIONS


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # If there's a POST request(Form submitted) enter statement.
    if request.method == 'POST':
        # Try:
        # Retrieve User Credential in the form

        # Hash the password

        # DML into MySQLdb
        pass


@app.route('/login', methods=['GET', 'POST'])
def signup():
    # If there's a POST request(Form submitted) enter statement.
    if request.method == 'POST':
        # Try:
        # Retrieve User Credential in the form

        # Retrieve account from sql (hash pass)
        # if successful
        # set session

        pass


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
        sql = "INSERT INTO posts (title, body, publish_time, category) VALUES (%s, %s, %s, %s)"
        val = (title, body, date, category)
        mycursor.execute(sql, val)
        mydb.commit()
        print("post added to database, redirecting to homepage")
        return redirect(url_for('index'))

    return render_template('/processes/createpost.html', form=form)



if __name__ == '__main__':
    app.run(debug=True)
