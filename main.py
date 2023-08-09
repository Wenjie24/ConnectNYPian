from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf.csrf import CSRFProtect
import mysql.connector
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import MySQLdb.cursors
from mysql.connector import Error
from datetime import date, timedelta
from forms import *
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import pyotp
import os

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=10)

# Config the Setting
app.config['SECRET_KEY'] = 'AAjACNiLqAjtjnW8DEonAAwUbd3jnroCdrtrYhlYc'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'

app.config['MYSQL_PASSWORD'] = 'wenjie'

app.config['MYSQL_DB'] = 'connectnypian_db'  # Standardised schema name
app.config['MYSQL_PORT'] = 3306

app.config['RECAPTCHA_PUBLIC_KEY'] = '6LfegionAAAAACW8DE2INwUbd3jnroCdrtrYhlYc'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LfegionAAAAAAAqNiLqaVAF_S2k0jtjvgXZ-CK1'
#app.config['TESTING'] = True #To disable captcha

admin_secret_key = '2d9b0f816ffdb77b8e09a46eaf30a1ec9077435a5073cd791aa397729ade5fc7b9a22888c978111461ab1345055b380d3d7571ce6120c8845a10e9f441cededc'

#Intialize MYSQL
mysql = MySQL(app)

#Enable CRSF
csrf = CSRFProtect(app)

#Enable 2FA
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

#Enable mail

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'ConnectNYPian@gmail.com'
app.config['MAIL_PASSWORD'] = 'zpuvubhesqjabipo'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

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
    else:
        return True

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
    val = str(account_id),
    result = execute_fetchone(sql, val)
    try:
        if result['locked_status'] == 'unlocked':
            return False
        elif result['locked_status'] == 'locked':
            print('account is locked')
            return True
    except TypeError:
        return False

def checksecurityquestions():
    sql = 'SELECT * FROM security_questions WHERE account_id = %s'
    val = str(session['login_id']),
    result = execute_fetchone(sql, val)
    if result:
        return True
    else:
        print('redirecting')
        return redirect(url_for('create_security_questions'))
# END OF EXTERNAL FUNCTIONS

@app.route('/')
def home():
    # Extract all the post from sql
    if check_login_status(): #Check for login
        print("logged in")
        if checksecurityquestions() != True:
            return checksecurityquestions()
        sql = 'SELECT * FROM posts INNER JOIN accounts on posts.account_id = accounts.account_id WHERE posts.account_id NOT IN (SELECT blocked_account_id FROM blocks WHERE blocker_account_id = %s) AND posts.account_id NOT IN (SELECT blocker_account_id FROM blocks WHERE blocked_account_id = %s) ORDER BY posts.post_timestamp desc'
        val = (str(session['login_id']), str(session['login_id']))
        feed = execute_fetchall(sql, val)
        sql = 'SELECT post_id FROM likes WHERE account_id = %s'
        val = str(session['login_id']),
        original_list = execute_fetchall(sql, val)
        liked_posts = [item['post_id'] for item in original_list]
        print('liked posts by user (post_id):', liked_posts)
        return render_template('index.html', feed=feed, liked_posts=liked_posts)
    else:
        print("Redirecting to sign up")
        return redirect(url_for('signup'))
    
@app.route('/school-specific')
def school_home():
    # Extract all the school-specific post from sql
    if check_login_status(): #Check for login
        print("logged in")
        if checksecurityquestions() != True:
            return checksecurityquestions()
        school_specific = True
        sql = 'SELECT school FROM students WHERE account_id = %s'
        val = str(session['login_id']),
        school = execute_fetchone(sql, val)
        sql = 'SELECT * FROM posts INNER JOIN accounts on posts.account_id = accounts.account_id INNER JOIN students ON posts.account_id = students.account_id WHERE students.school = %s AND posts.account_id NOT IN (SELECT blocked_account_id FROM blocks WHERE blocker_account_id = %s) AND posts.account_id NOT IN (SELECT blocker_account_id FROM blocks WHERE blocked_account_id = %s) ORDER BY posts.post_timestamp desc'
        val = (str(school['school']), str(session['login_id']), str(session['login_id']))
        feed = execute_fetchall(sql, val)
        sql = 'SELECT post_id FROM likes WHERE account_id = %s'
        val = str(session['login_id']),
        original_list = execute_fetchall(sql, val)
        liked_posts = [item['post_id'] for item in original_list]
        print('liked posts by user (post_id):', liked_posts)
        return render_template('index.html', feed=feed, liked_posts=liked_posts, school_specific=school_specific)
    else:
        print("Redirecting to sign up")
        return redirect(url_for('signup'))

@app.route('/user/<int:id>')
def user(id):
    if check_login_status(): #Check for login status
        if checksecurityquestions() != True:
            return checksecurityquestions()
        try:
            result = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s', (id,)) #Try to retrieve account id
            posts = execute_fetchall('SELECT * FROM posts WHERE account_id = %s ORDER BY post_timestamp desc', (id, ))
            following = execute_fetchall('SELECT count(*) following FROM follow_account WHERE follower_id = %s', (id,))
            followers = execute_fetchall('SELECT count(*) followers FROM follow_account WHERE followee_id = %s', (id,))
            post_no = execute_fetchall('SELECT count(*) posts FROM posts WHERE account_id = %s', (id,))
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
                    if following:
                        following = following[0]['following']
                    else:
                        following = 0
                    if followers:
                        followers = followers[0]['followers']
                    else:
                        followers = 0
                    if post_no:
                        post_no = post_no[0]['posts']
                    else: 
                        post_no = 0

                except Error as e:
                    print("Error in retrieving data")
                else:
                    if check_session('login_id') == account_id: #Check if target account is logged in
                        print(account_id)
                        return render_template('profile.html', is_owner=True, account_id=account_id, school_email=school_email, username=username, created_timestamp=created_timestamp, posts=posts, is_following=False, following=following, followers=followers, post_no=post_no, is_blocked=False)
                        print("Account id logged in")
                    else:
                        print("Account id not logged in")
                        
                        # check if following the user
                        following_list = execute_fetchall('SELECT * FROM follow_account WHERE follower_id = %s', (str(session['login_id']), ))
                        following_list = [item['followee_id'] for item in following_list]
                        if following_list:
                            for account in following_list:
                                if int(account) == int(id):
                                    is_following = True
                                    print('TRUE')
                                    break
                                else:
                                    is_following = False
                                    print("FALSE")
                        else:
                            is_following = False
                        
                        # check if blocked the user
                        blocked_list = execute_fetchall('SELECT * FROM blocks WHERE blocker_account_id = %s', (str(session['login_id']), ))
                        blocked_list = [item['blocked_account_id'] for item in blocked_list]
                        if blocked_list:
                            for account in blocked_list:
                                if int(account) == int(id):
                                    is_blocked = True
                                    break
                                else:
                                    is_blocked = False
                        else:
                            is_blocked = False

                        return render_template('profile.html',  account_id=account_id, school_email=school_email, username=username, created_timestamp=created_timestamp, posts=posts, is_following=is_following, following=following, followers=followers, post_no=post_no, is_blocked=is_blocked)
                    

            else: #If account id not exist
                return 'no such account page'


    else:
        return redirect(url_for('signup'))



@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        #Check for same token
        email = serializer.loads(token, salt='sign_up', max_age=300)
    except SignatureExpired:
        return 'Token Expired, please sign up again.'
    except Exception:
        return 'Unknown error has occurred'
    else:

        if check_session('temp_sign_up_dict'):

            #If there's token and is false
            token_detail = execute_fetchone('SELECT token_type, used_boolen FROM verification_token WHERE token = %s', (token,))
            if token_detail['token_type'] == 'signup' and token_detail['used_boolen'] == False:

                #Update the table that the token is used
                execute_commit('UPDATE used_boolen SET used_boolen = %s WHERE token = %s', (True, token))

                try:
                    dict_value = check_session('temp_sign_up_dict')
                    hashed_password = dict_value['hashed_password']
                    email = dict_value['email']
                    username = dict_value['username']
                    school = dict_value['school']

                except Exception:
                    return 'Unknown Error Has Occured'
                else:
                     # Inserting data into account: account_id, email, username, date_created
                    execute_commit('INSERT INTO accounts (hashed_pass, school_email, username) VALUES (%s, %s, %s)',(hashed_password, email, username))
                    # Inserting school into sub table
                    account_id = execute_fetchone('SELECT account_id FROM accounts WHERE username = %s', (username, ))
                    execute_commit('INSERT INTO students (account_id, school) VALUES (%s, %s)', (account_id['account_id'], school))
                    print("Account created")
                    return "Token Valid, Account created, Please log in to continue."
            else:
                return 'Token not exist or smth la'
    finally:
        #Remove user dict if expired
        remove_session('temp_sign_up_dict')







@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if check_login_status():
        return redirect(url_for('home'))

    #Declare username/email error/signup_status for error message
    username_error = None
    email_error = None
    signup_status = None
    password_error = None

    form = signup_form(request.form)
    # If there's a POST request(Form submitted) enter statement.
    if request.method == 'POST' and form.validate():
        print("Signing Up")
        # Try:
        # Retrieve User Credential in the form
        try:
            username = request.form['username']
            password = request.form['password']
            reenterpassword = request.form['reenterpassword']
            school = form.school.data
            hashed_password = bcrypt.generate_password_hash(password)  # Hash the password
            email = request.form['email']
            if password == reenterpassword:
                password_same = True
            else:
                password_same = False
            username_exist = execute_fetchone('SELECT username FROM accounts WHERE username = %s', (username,))
            email_exist = execute_fetchone('SELECT school_email FROM accounts WHERE school_email = %s', (email,))
        except Error as e:
            print("Error trying to retrieve sign up for credential\n", e)
        else:
            if not username_exist and not email_exist and password_same: # If username and email is avaliable
                if hashed_password:# If password is hashed and ready to use
                    # Try 2FA to confirm email exist

                    #Generate a url serializer
                    token = serializer.dumps(email, salt='sign_up')
                    print(f'This is your token:\n{token}')

                    #If there's a token, create a session with all user value inside (So we can create the account after verifying 2fa in other route)
                    if token:
                        dict_value = {'username': username, 'hashed_password': hashed_password, 'email': email, 'school': school}
                        create_session('temp_sign_up_dict', dict_value)
                        execute_commit('INSERT INTO verification_token VALUES (%s, %s, %s)', (token, ))
                        signup_status = f'An verification token has been sent to {email}'

                        message = Message(f'Email verification for {email}', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
                        verification_link = url_for('confirm_email', token=token, _external=True)
                        message.body = f'Here is your verification link for Username: {username}\n\n{verification_link}\n\nVerification link will expire in 5 minutes.'
                        mail.send(message)

                    else: # If the token has issue
                        signup_status = '2FA token generation error has occurred'


                    #Tell user that email verification has been send

            else:  #If username and email is not avaliable
                print("Sign up fail")
                if username_exist: #If only email exist
                    print("username exist")
                    username_error= True
                    email_error = False
                    password_error = False
                if email_exist: #If only email exist
                    print("Email exist")
                    email_error=True
                    username_error = False
                    password_error = False

                if username_exist and email_exist: #If both exist
                    username_error = True
                    email_error = True
                    password_error = False
                
                if not password_same:
                    username_error = False
                    email_error = False
                    password_error = True

                if username_exist and not password_same:
                    username_error = True
                    email_error = False
                    password_error = True

                if username_exist and email_error and not password_same:
                    username_error = True
                    email_error = True
                    password_error = True

                if email_error and not password_same:
                    username_error = False
                    email_error = True
                    password_error = True

        # DML into MySQLdb

    return render_template('processes/signup.html', form=form, username_error=username_error, email_error=email_error, signup_status=signup_status, password_error=password_error)

@app.route('/admin')
def admin():
    print("admin!!")
    return render_template('processes/admin.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if check_login_status():
        return redirect(url_for('home'))


    form=login_form(request.form)

    # Setting error message
    not_logged_in = False
    account_locked = False
    invalid_pass_or_username = False

    # If there's a POST request(Form submitted) enter statement.
    if request.method == 'POST' and form.validate(): # If a form is submitted
        try:
            # Retrieve User Credential in the form
            username = request.form['username']
            password = request.form['password']
            result = execute_fetchone('SELECT * FROM accounts WHERE username = %s', (username,)) # Getting data from database
        except Error as e:
            print("Unknown error occurred while retrieving user credential.\n", e)
        else:
            #If is logging in as admin
            if username == 'administrator' and password == admin_secret_key:
                create_session('login_status', True)
                create_session('login_id', -1)
                return redirect(url_for('admin'))
            




            # If there's result from retrieving
            if result:
                print("Retrieving data")
                # Assigning value from the data retrieved
                hashed_pass = result['hashed_pass']
                account_id = result['account_id']
                username = result['username']
                #If able to retrieve, continue
                # Checking if the there's a result from the sql query and checking the value of both hash function
                if bcrypt.check_password_hash(hashed_pass, password):
                    if checklockedstatus(account_id) == False:
                        try:
                            #If login success, try to create session for the user
                            create_session('login_status', True)
                            create_session('login_id', account_id)
                            create_session('username', username)
                            session.permanent = True

                            #Reset account status
                            sql = 'DELETE FROM account_status WHERE account_id = %s AND failed_attempts < 5'
                            val = session['login_id'],
                            execute_commit(sql, val)
                            
                            #check if user has done security questions, redirects to page if has not
                            security_questions = execute_fetchall('SELECT * FROM security_questions WHERE account_id = %s', (str(session['login_id']), ))
                            print(security_questions)
                            if security_questions == ():
                                return redirect(url_for('create_security_questions'))

                        except Error as e: #If login fail
                            print("Login Fail")
                            print("Unknown error occurred while trying to create session for user.\n", e)
                        else:
                            print("Login success")
                            return redirect(url_for('home'))
                    else:
                        #even if correct pass, but locked
                        account_locked = True

                elif bcrypt.check_password_hash(hashed_pass, password) == False:
                    print("Wrong password for:", username)
                    sql = 'SELECT * FROM account_status WHERE account_id = %s'

                    val = account_id,

                    account_status = execute_fetchone(sql, val)
                    if account_status:
                        sql = 'UPDATE account_status SET failed_attempts = failed_attempts + 1 WHERE account_id = %s'
                        execute_commit(sql, val)

                        failed_account = execute_fetchone('SELECT failed_attempts FROM account_status WHERE account_id = %s', (account_id,))
                        print(failed_account)
                        if int(failed_account['failed_attempts']) >= 5:
                            sql = 'UPDATE account_status SET locked_status = %s WHERE account_id = %s'
                            val = ('locked', account_id)
                            execute_commit(sql, val)
                            print('account with account id of:', account_id, 'has been locked')
                            # account locked
                            account_locked = True
                    else:
                        sql = 'INSERT INTO account_status (account_id, failed_attempts) VALUES (%s, 1)'
                        execute_commit(sql, val)


            # if no result
            invalid_pass_or_username = True



    return render_template('processes/login.html', form=form, account_locked=account_locked, invalid_pass_or_username=invalid_pass_or_username)

@app.route('/logout')
def logout():
    remove_session('login_status')
    remove_session('login_id')
    remove_session('username')
    return redirect(url_for('home'))


@app.route('/reset_pass')
def reset_pass():
    if check_login_status():
        user_id = check_session('login_id')

        account_details = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s', (user_id,))
        user_email = account_details['school_email']

        token = serializer.dumps(user_email, salt='reset_pass')


        message = Message(f'Reset Password', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
        verification_link = url_for('reset_pass_confirmed', token=token, _external=True)
        message.body = f'Here is your reset Link\n\n{verification_link}\n\nVerification link will expire in 5 minutes.'
        mail.send(message)

        return f'reset link send to {user_email}'

    else:
        return 'please log in'

@app.route('/reset_pass_confirmed/<token>', methods=['GET','POST'])
def reset_pass_confirmed(token):
    try:
        serializer.loads(token, salt='reset_pass', max_age=300)
    except SignatureExpired:
        return 'token expired'
    else:


        form = reset_pass_form(request.form)

        reset_link = url_for('reset_pass_confirmed', token=token, _external=True)

        if request.method == 'POST' and form.validate():
            password = request.form['password']
            hashed_pass = bcrypt.generate_password_hash(password)
            sql_query = 'UPDATE accounts SET hashed_pass = %s WHERE account_id = %s'
            val = (hashed_pass, check_session('login_id'),)
            result = execute_commit(sql_query, val)

            
            if result:
                return 'password updated'
            else:
                return 'error while updating password'




        else:
            return render_template('/processes/reset_pass.html', form=form, reset_link=reset_link)


@app.route('/createpost', methods=['GET', 'POST'])
def createpost():
    if 'login_status' not in session:
        return redirect(url_for('login'))
    
    if checksecurityquestions() != True:
            return checksecurityquestions()
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
            if checksecurityquestions() != True:
                return checksecurityquestions()
            sql = "INSERT INTO likes (account_id, post_id) VALUES (%s, %s)"
            val = (session['login_id'], post_id)
            execute_commit(sql, val)
            sql = 'UPDATE posts SET like_count = like_count + 1 WHERE post_id = %s'
            val = (post_id, )
            execute_commit(sql, val)
        return redirect(url_for('home'))

    except Error as e:
        print("Error creating like: ", e)

@app.route('/removelike/<post_id>')
def removelike(post_id):
    try:
        if 'login_id' in session:
            if checksecurityquestions() != True:
                return checksecurityquestions()
            sql = "DELETE FROM likes WHERE post_id = %s AND account_id = %s"
            val = (post_id, session['login_id'])
            execute_commit(sql, val)
            sql = 'UPDATE posts SET like_count = like_count - 1 WHERE post_id = %s'
            val = (post_id, )
            execute_commit(sql, val)
        return redirect(url_for('home'))
    
    except Error as e:
        print("Error removing like: ", e)

@app.route('/deletepost/<post_id>')
def deletepost(post_id):
    try:
        if 'login_id' in session:
            try:
                if checksecurityquestions() != True:
                    return checksecurityquestions()
                sql = 'SELECT account_id FROM posts WHERE post_id = %s'
                val = (post_id, )
                account_id = execute_fetchone(sql, val)
                print(account_id)
            except Error as e:
                print('Error executing sql:', e)
            else:
                if session['login_id'] == account_id['account_id']:
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
            if checksecurityquestions() != True:
                return checksecurityquestions()
            sql = 'SELECT * FROM posts INNER JOIN accounts ON posts.account_id = accounts.account_id WHERE posts.post_id = %s'
            val = (str(post_id), )
            post = execute_fetchone(sql, val)
            form = create_comment(request.form)
            sql = 'SELECT post_id FROM likes WHERE account_id = %s'
            val = (str(session['login_id']), )
            original_list = execute_fetchall(sql, val)
            liked_posts = [item['post_id'] for item in original_list]
            sql = 'SELECT * FROM comments INNER JOIN accounts ON comments.account_id = accounts.account_id WHERE comments.post_id = %s ORDER BY comments.comment_timestamp desc'
            val = (str(post_id), )
            comments = execute_fetchall(sql, val)

            if request.method == 'POST' and form.validate():
                body = form.body.data

                sql = "INSERT INTO comments (body, account_id, post_id) VALUES (%s, %s, %s)"
                val = (body, session['login_id'], post_id)
                execute_commit(sql, val)
                print("comment added to database")
                sql = 'UPDATE posts SET comment_count = comment_count + 1 WHERE post_id = %s'
                val = (post_id, )
                execute_commit(sql, val)
                sql = 'SELECT * FROM comments INNER JOIN accounts ON comments.account_id = accounts.account_id WHERE comments.post_id = %s ORDER BY comments.comment_timestamp desc'
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
            try:
                if checksecurityquestions() != True:
                    return checksecurityquestions()
                sql = 'SELECT account_id FROM comments WHERE comment_id = %s'
                val = (str(comment_id), )
                account_id = execute_fetchone(sql, val)
            except Error as e:
                print('Error executing sql:', e)
            else:
                if session['login_id'] == account_id['account_id']:
                    sql = 'DELETE FROM comments WHERE comment_id = %s'
                    val = (str(comment_id), )
                    execute_commit(sql, val)
                    print('comment deleted')
                    sql = 'UPDATE posts SET comment_count = comment_count - 1 WHERE post_id = %s'
                    val = (post_id, )
                    execute_commit(sql, val)
            return redirect(url_for('comments', post_id=post_id))
    
    except Error as e:
        print('Error deleting comment:', e)

@app.route('/create-security-questions', methods=['GET', 'POST'])
def create_security_questions():
    try:
        if 'login_id' in session:
            form = security_questions(request.form)
            if request.method == 'POST' and form.validate():
                qn1 = form.qn1.data
                qn1_ans = form.qn1_ans.data
                qn2 = form.qn2.data
                qn2_ans = form.qn2_ans.data
                sql = 'INSERT INTO security_questions (account_id, qn1, qn1_ans, qn2, qn2_ans) VALUES (%s, %s, %s, %s, %s)'
                val = (str(session['login_id']), qn1, qn1_ans, qn2, qn2_ans)
                execute_commit(sql, val)
                return redirect(url_for('home'))
            return render_template('/processes/security_questions.html', form=form)
        else:
            return redirect(url_for('login'))

    except Error as e:
        print("Error creating security qns:", e)

@app.route('/follow/<account_id>')
def follow_account(account_id):
    try:
        if 'login_id' in session:
            if checksecurityquestions() != True:
                return checksecurityquestions()
            sql = 'INSERT INTO follow_account (follower_id, followee_id) VALUES (%s, %s)'
            val = (str(session['login_id']), account_id)
            execute_commit(sql, val)
            is_following = True
            return redirect(url_for('user', id=account_id, is_following=is_following))

        else:
            return redirect(url_for('login'))

    except Error as e:
        print('Error following account:', e)

@app.route('/unfollow/<account_id>')
def unfollow_account(account_id):
    try:
        if 'login_id' in session:
            if checksecurityquestions() != True:
                return checksecurityquestions()
            sql = 'DELETE FROM follow_account WHERE follower_id = %s and followee_id = %s'
            val = (str(session['login_id']), account_id)
            execute_commit(sql, val)
            is_following = False
            return redirect(url_for('user', id=account_id, is_following=is_following))

        else:
            return redirect(url_for('login'))

    except Error as e:
        print('Error following account:', e)

@app.route('/block/<account_id>')
def block(account_id):
    try:
        if 'login_id' in session:
            if checksecurityquestions() != True:
                return checksecurityquestions()
            
            if str(session['login_id']) == str(account_id):
                return redirect(url_for('user', id=account_id, is_blocked=False))
            
            sql = 'SELECT * FROM blocks WHERE blocker_account_id = %s AND blocked_account_id = %s'
            val = (str(session['login_id']), account_id)
            blocked = execute_fetchall(sql, val)
            if blocked:
                is_blocked = True
            else:
                sql = 'INSERT INTO blocks (blocker_account_id, blocked_account_id) VALUES (%s, %s)'
                execute_commit(sql, val)
                sql = 'DELETE FROM follow_account WHERE follower_id = %s and followee_id = %s'
                execute_commit(sql, val)
                is_blocked = True
            return redirect(url_for('user', id=account_id, is_blocked=is_blocked))
        
        else:
            return redirect(url_for('login'))
        
    except Error as e:
        print('Error blocking account:', e)

@app.route('/unblock/<account_id>')
def unblock(account_id):
    try:
        if 'login_id' in session:
            if checksecurityquestions() != True:
                return checksecurityquestions()
            
            sql = 'DELETE FROM blocks WHERE blocker_account_id = %s AND blocked_account_id = %s'
            val = (str(session['login_id']), account_id)
            execute_commit(sql, val)
            is_blocked = False
        
            return redirect(url_for('user', id=account_id, is_blocked=is_blocked))
        
        
        

        
        else:
            return redirect(url_for('login'))
        
    except Error as e:
        print('Error unblocking account:', e)

@app.route('/report-post/<post_id>', methods=['GET', 'POST'])
def report_post(post_id):
    try:
        if 'login_id' in session:
            if checksecurityquestions() != True:
                return checksecurityquestions()
            form = report_form(request.form)
            if request.method == 'POST' and form.validate():
                reason = form.reason.data
                sql = 'INSERT INTO report_post (reporter_id, post_id, reason) VALUES (%s, %s, %s)'
                val = (str(session['login_id']), post_id, reason)
                execute_commit(sql, val)
                return redirect(url_for('home'))
            return render_template('/processes/report_post.html', form=form, post_id=post_id)
        else:
            return redirect(url_for('login'))
        
    except Error as e:
        print('Error reporting user:', e)





if __name__ == '__main__':
    app.run(debug=True)


#Security Issue
#1) account cant be locked if it does not exist
#2) Check database before performing query instead of session