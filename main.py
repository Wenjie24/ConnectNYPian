from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import MySQLdb.cursors
from mysql.connector import Error
from datetime import date, timedelta
from forms import *

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=1)

# Config the Setting
app.config['SECRET_KEY'] = 'helpmyasshurt'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'

app.config['MYSQL_PASSWORD'] = 'wenjie'

app.config['MYSQL_DB'] = 'connectnypian_db'  # Standardised schema name
app.config['MYSQL_PORT'] = 3306

app.config['RECAPTCHA_PUBLIC_KEY'] = '6LfegionAAAAACW8DE2INwUbd3jnroCdrtrYhlYc'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LfegionAAAAAAAqNiLqaVAF_S2k0jtjvgXZ-CK1'
app.config['TESTING'] = True #To disable captcha

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
            return session[session_key]
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

def checklike(post_id):
    sql = 'SELECT * FROM likes WHERE account_id = %s AND post_id = %s'
    val = (session['login_id'], post_id)
    result = execute_fetchall(sql, val)
    if result:
        return True
    else:
        return False

def checklockedstatus(account_id):
    sql = 'SELECT locked_status FROM account_status WHERE account_id = %s'
    val = str(account_id)
    result = execute_fetchone(sql, val)
    try:
        if result['locked_status'] == 'unlocked':
            return False
        elif result['locked_status'] == 'locked':
            print('account is locked')
            return True
    except TypeError:
        return False
    
    
def lockaccount(account_id):
    sql = 'SELECT failed_attempts FROM account_status WHERE account_id = %s'
    val = str(account_id)
    result = execute_fetchone(sql, val)
    print(result)
    if int(result['failed_attempts']) >= 5:
        sql = 'UPDATE account_status SET locked_status = %s WHERE account_id = %s'
        val = ('locked', account_id)
        execute_commit(sql, val)
        print('account with account id of:',account_id, 'has been locked')


# END OF EXTERNAL FUNCTIONS
@app.route('/')
def home():
    # Extract all the post from sql
    if check_login_status(): #Check for login
        print("logged in")
        sql = 'SELECT * FROM posts INNER JOIN accounts on posts.account_id = accounts.account_id'
        feed = execute_fetchall(sql)
        sql = 'SELECT post_id FROM likes WHERE account_id = %s'
        val = str(session['login_id'])
        original_list = execute_fetchall(sql, val)
        liked_posts = [item['post_id'] for item in original_list]
        print('liked posts by user (post_id):', liked_posts)
        return render_template('index.html', feed=feed, liked_posts=liked_posts)
    else:
        return redirect(url_for('signup'))
@app.route('/user/<int:id>')
def user(id):
    if check_login_status(): #Check for logn status
        try:
            result = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s', (id,)) #Try to retrieve account id

        except Error as e: # if error
            print("error retrieving account id")
            #Redirect to error page
        else: # if able to retrieve
            if result: #If account id exist
                try:
                    account_id = result['account_id']
                    school_email = result['school_email']
                    username = result['username']
                    created_timestamp = result['created_timestamp']

                except Error as e:
                    print("Error in retrieving data")
                else:
                    if check_session('login_id') == account_id: #Check if target account is logged in
                        print(account_id)
                        return render_template('profile.html', is_owner=True, account_id=account_id, school_email=school_email, username=username, created_timestamp=created_timestamp)
                        print("Account id logged in")
                    else:
                        print("Account id not logged in")
                        return render_template('profile.html',  account_id=account_id, school_email=school_email, username=username, created_timestamp=created_timestamp)

            else: #If account id not exist
                return 'no such account page'


    else:
        return redirect(url_for('signup'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if check_login_status():
        return redirect(url_for('home'))

    #Declare username/email error for error message
    username_error = None
    email_error = None

    form = signup_form(request.form)
    # If there's a POST request(Form submitted) enter statement.
    if request.method == 'POST' and form.validate():
        print("Signing Up")
        # Try:
        # Retrieve User Credential in the form
        try:
            username = request.form['username']
            password = request.form['password']
            hashed_password = bcrypt.generate_password_hash(password)  # Hash the password
            email = request.form['email']
            username_exist = execute_fetchone('SELECT username FROM accounts WHERE username = %s', (username,))
            email_exist = execute_fetchone('SELECT school_email FROM accounts WHERE school_email = %s', (email,))
        except Error as e:
            print("Error trying to retrieve sign up for credential\n", e)
        else:
            if not username_exist and not email_exist: #If username and email is avaliable
                if hashed_password:
                    # Inserting data into account: account_id, email, username, date_created
                    execute_commit('INSERT INTO accounts (hashed_pass, school_email, username) VALUES (%s, %s, %s)',(hashed_password, email, username))
                    print("Account created")
                    return redirect(url_for('login'))
            else:  #If username and email is not avaliable
                print("Sign up fail")
                if username_exist: #If only email exist
                    print("username exist")
                    username_error= True
                    email_error = False
                if email_exist: #If only email exist
                    print("Email exist")
                    email_error=True
                    username_error = False

                if username_exist and email_exist: #If both exist
                    username_error = True
                    email_error = True




        # DML into MySQLdb

    return render_template('processes/signup.html', form=form, username_error=username_error, email_error=email_error)



@app.route('/login', methods=['GET', 'POST'])
def login():
    if check_login_status():
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
            if result and bcrypt.check_password_hash(hashed_pass, password) and checklockedstatus(account_id) == False:
                try:
                    #If login success, try to create session for the user
                    create_session('login_status', True)
                    create_session('login_id', account_id)
                    create_session('username', username)
                    sql = 'DELETE FROM account_status WHERE account_id = %s AND failed_attempts < 5'
                    val = str(session['login_id'])
                    execute_commit(sql, val)
                except Error as e: #If login fail
                    print("Login Fail")
                    print("Unknown error occurred while trying to create session for user.\n", e)
                else:
                    print("Login success")
                    return redirect(url_for('home'))
            
            elif result and bcrypt.check_password_hash(hashed_pass, password) == False:
                print("Wrong password for:", username)
                sql = 'SELECT * FROM account_status WHERE account_id = %s'
                val = str(account_id)
                account_status = execute_fetchone(sql, val)
                if account_status:
                    sql = 'UPDATE account_status SET failed_attempts = failed_attempts + 1 WHERE account_id = %s'
                    execute_commit(sql, val)
                    lockaccount(account_id)
                else:
                    sql = 'INSERT INTO account_status (account_id, failed_attempts) VALUES (%s, 1)'
                    execute_commit(sql, val)
                    return redirect(url_for('login'))


    return render_template('processes/login.html', form=form)

@app.route('/logout')
def logout():
    remove_session('login_status')
    remove_session('login_id')
    remove_session('username')
    return redirect(url_for('home'))




@app.route('/createpost', methods=['GET', 'POST'])
def createpost():
    if 'login_status' not in session:
        return redirect(url_for('login'))
    
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

@app.route('/createlike/<post_id>/')
def createlike(post_id):
    try:
        if 'login_id' in session and checklike(post_id) == False:
            sql = "INSERT INTO likes (account_id, post_id) VALUES (%s, %s)"
            val = (session['login_id'], post_id)
            execute_commit(sql, val)
        return redirect(url_for('home'))

    except Error as e:
        print("Error creating like: ", e)

@app.route('/removelike/<post_id>')
def removelike(post_id):
    try:
        if 'login_id' in session:
            sql = "DELETE FROM likes WHERE post_id = %s AND account_id = %s"
            val = (post_id, session['login_id'])
            execute_commit(sql, val)
        return redirect(url_for('home'))
    
    except Error as e:
        print("Error removing like: ", e)

@app.route('/deletepost/<post_id>')
def deletepost(post_id):
    try:
        if 'login_id' in session:
            sql = 'DELETE FROM comments WHERE post_id = %s'
            val = (post_id, )
            execute_commit(sql, val)
            sql = 'DELETE FROM likes WHERE post_id = %s'
            execute_commit(sql, val)
            sql = 'DELETE FROM posts WHERE post_id = %s'
            execute_commit(sql, val)
        return redirect(url_for('home'))

    except Error as e:
        print("Error deleting post: ", e)

@app.route('/comments/<post_id>', methods=['GET', 'POST'])
def comments(post_id):
    try:
        if 'login_id' not in session:
            return redirect(url_for('login'))

        if 'login_id' in session:
            sql = 'SELECT * FROM posts INNER JOIN accounts ON posts.account_id = accounts.account_id WHERE posts.post_id = %s'
            val = (str(post_id), )
            post = execute_fetchone(sql, val)
            form = create_comment(request.form)
            sql = 'SELECT post_id FROM likes WHERE account_id = %s'
            val = (str(session['login_id']), )
            original_list = execute_fetchall(sql, val)
            liked_posts = [item['post_id'] for item in original_list]
            sql = 'SELECT * FROM comments INNER JOIN accounts ON comments.account_id = accounts.account_id WHERE comments.post_id = %s'
            val = (str(post_id), )
            comments = execute_fetchall(sql, val)

            if request.method == 'POST':
                body = form.body.data

                sql = "INSERT INTO comments (body, account_id, post_id) VALUES (%s, %s, %s)"
                val = (body, session['login_id'], post_id)
                execute_commit(sql, val)
                print("comment added to database")
                sql = 'SELECT * FROM comments INNER JOIN accounts ON comments.account_id = accounts.account_id WHERE comments.post_id = %s'
                val = (str(post_id), )
                comments = execute_fetchall(sql, val)
                return render_template('/processes/comments.html', post=post, liked_posts=liked_posts, form=form, comments=comments)
    
        return render_template('/processes/comments.html', post=post, liked_posts=liked_posts, form=form, comments=comments)

    except Error as e:
        print('Error creating comment: ', e)

@app.route('/deletecomment/<post_id>/<comment_id>')
def deletecomment(post_id, comment_id):
    try:
        if 'login_id' in session:
            sql = 'DELETE FROM comments WHERE comment_id = %s'
            val = (str(comment_id), )
            execute_commit(sql, val)
            print('comment deleted')
            sql = 'SELECT post_id FROM posts WHERE p'
            return redirect(url_for('comments', post_id=post_id))
    
    except Error as e:
        print('Error deleting comment:', e)





if __name__ == '__main__':
    app.run(debug=True)
