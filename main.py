import datetime
import json
from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf.csrf import CSRFProtect
import mysql.connector
from MySQLdb import IntegrityError
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import MySQLdb.cursors
from mysql.connector import Error
from datetime import date, timedelta
from forms import *
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from functools import wraps
from apscheduler.schedulers.background import BackgroundScheduler

import pyotp
import os

app = Flask(__name__)


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

#Enable CRSF Protection
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



#Enable tasked scheduler
def update_superadmin_sql():
    print()
    print('Generating a super admin key')
    print('Key generated: 1nfA(8nf1q8209M.FAWg81N@!nf19ngUA.sngfv091n3fvg(NA')
    print('Updating SuperAdmin SQL on', datetime.datetime.now())
    print()

scheduler = BackgroundScheduler()
scheduler.add_job(update_superadmin_sql, 'interval', hours=24, id='do_job_1')
scheduler.start()


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

def admin_login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_status' in session:
            pass
        else:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return wrap

def superadmin_login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_status' in session and 'superadmin_status' in session:
            pass
        else:
            return redirect(url_for('superadmin_login'))
        return f(*args, **kwargs)
    return wrap

def check_security_questions(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if check_login_status():
            if 'superadmin_status' in session:
                return redirect(url_for('superadmin'))
            sql = 'SELECT * FROM security_questions WHERE account_id = %s'
            val = str(session['login_id']),
            result = execute_fetchone(sql, val)
            if result:
                pass
            else:
                return redirect(url_for('create_security_questions'))

            return f(*args, **kwargs)
        else: return redirect(url_for('signup'))
    return wrap

def mergeSort(theList):
    # Check the base case - the list contains a single item
    if len(theList) <= 1:
        return theList
    else:
        # Compute the midpoint
        mid = len(theList) // 2

        # Split the list and perform the recursive step
        leftHalf = mergeSort(theList[:mid])
        rightHalf = mergeSort(theList[mid:])

        # Merge the two sorted sublists
        newList = mergeSortedLists(leftHalf, rightHalf)
        return newList

def mergeSortedLists(a, b):
    c = []
    while a != [] and b != []:
        if a[0] < b[0]:
            c.append(a[0])
            a.remove(a[0])

        elif a[0] > b[0]:
            c.append(b[0])
            b.remove(b[0])

    while a != [] and b == []:
        c.append(a[0])
        a.remove(a[0])

    while a == [] and b != []:
        c.append(b[0])
        b.remove(b[0])

    return c

def check_common_password(arr, target):
    low = 0
    high = len(arr) - 1

    while low <= high:
        mid = (low + high) // 2
        if arr[mid] == target:
            return True
        elif arr[mid] < target:
            low = mid + 1
        else:
            high = mid - 1

    return False

def containsLetterAndNumber(input):
    return any(x.isalpha() for x in input) and any(x.isnumeric() for x in input)

def create_alnum_pw(password):
    list1 = []
    for i in password:
        if i.isalnum():
            if i.isalpha():
                list1.append(i.lower())
            else:
                list1.append(i)

    return ''.join(str(i) for i in list1)
# END OF EXTERNAL FUNCTIONS


common_passwords_list = [] #list of 10k most common passwords
common_passwords = open('10k-most-common.txt', 'r')
for line in common_passwords:
    if containsLetterAndNumber(line):
        common_passwords_list.append(line.rstrip())

common_passwords_list = mergeSort(common_passwords_list)

# DYNAMIC SESSION LIFE
@app.before_request
def before_request():
    #Dynamic session life_time for inactivity
    if check_login_status():# if logged in
        app.permanent_session_lifetime = timedelta(minutes=5)
        print(app.permanent_session_lifetime, ' - session time resetted!')
#END

@app.errorhandler(404)
def error_page(e):
    return 'This is a error page la fuck, if you want see debug ownself comment out the @app.errorhandler(404)'

@app.route('/')
@check_security_questions
def home():
    # Extract all the post from sql
    if check_login_status(): #Check for login
        print("logged in")
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
@check_security_questions
def school_home():
    # Extract all the school-specific post from sql
    if check_login_status(): #Check for login
        print("logged in")
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
@check_security_questions
def user(id):
    if check_login_status(): #Check for login status
        try:
            result = execute_fetchone('SELECT * FROM accounts a INNER JOIN students s ON a.account_id = s.account_id WHERE a.account_id = %s', (id,)) #Try to retrieve account id
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
                    school = result['school']
                    account_class = result['class']
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
                        return render_template('profile.html', is_owner=True, account_id=account_id, school_email=school_email, username=username, created_timestamp=created_timestamp, posts=posts, is_following=False, following=following, followers=followers, post_no=post_no, is_blocked=False, school=school, account_class=account_class)
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

                        return render_template('profile.html',  account_id=account_id, school_email=school_email, username=username, created_timestamp=created_timestamp, posts=posts, is_following=is_following, following=following, followers=followers, post_no=post_no, is_blocked=is_blocked, school=school, account_class=account_class)


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
            #If there's token and is false
            token_detail = execute_fetchone('SELECT * FROM verification_token WHERE token = %s', (token,))
            if token_detail['token_type'] == 'signup' and token_detail['used_boolean'] == False:
                try:

                    hashed_password = token_detail['hashed_pass']
                    email = token_detail['school_email']
                    username = token_detail['username']
                    school = token_detail['school']

                    print(email)

                except Exception as e:
                    return f'Unknown Error Has Occurred\n {e}'
                else:

                    try:
                         # Inserting data into account: account_id, email, username, date_created
                        execute_commit('INSERT INTO accounts (hashed_pass, school_email, username, class) VALUES (%s, %s, %s, %s)',(hashed_password, email, username, 'student'))
                        # Inserting school into sub table
                        account_id_tuple = execute_fetchone('SELECT account_id FROM accounts WHERE username = %s', (username, ))
                        account_id = account_id_tuple['account_id']
                        execute_commit('INSERT INTO students (account_id, school) VALUES (%s, %s)', (str(account_id), school))

                    except IntegrityError:
                        return 'Cant create account. account already exist.'
                    else:
                        # Inserting school into sub table
                        account_id_tuple = execute_fetchone('SELECT account_id FROM accounts WHERE username = %s',
                                                            (username,))
                        account_id = account_id_tuple['account_id']
                        #execute_commit('INSERT INTO students (account_id, school) VALUES (%s, %s)',
                                       #(account_id, school))

                        print("CURRENT ACCOUNT ID TO BE ADDED IN ACCOUNT STATUS: ", account_id)

                        # Make a account status for him
                        execute_commit('INSERT INTO account_status (account_id, enabled_2fa) VALUES (%s,"enabled")',
                                       (account_id,))

                        # Update the table that the token is used
                        execute_commit(
                            'UPDATE verification_token SET used_boolean = True, account_id = %s WHERE token = %s',
                            (account_id, token))

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
    common_password_error = None

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
            alnum_pw = create_alnum_pw(password)

            # check for signup errors
            if password == reenterpassword:
                password_same = True
            else:
                password_same = False
            username_exist = execute_fetchone('SELECT username FROM accounts WHERE username = %s', (username,))
            email_exist = execute_fetchone('SELECT school_email FROM accounts WHERE school_email = %s', (email,))
            if password_same == True:
                if check_common_password(common_passwords_list, alnum_pw) == True:
                    common_password = True
                else: common_password = False
            else: common_password = False


        except Error as e:
            print("Error trying to retrieve sign up for credential\n", e)
        else:
            if not username_exist and not email_exist and not common_password and password_same: # If username and email is avaliable
                if hashed_password:# If password is hashed and ready to use
                    # Try 2FA to confirm email exist

                    #Generate a url serializer
                    token = serializer.dumps(email, salt='sign_up')
                    print(f'This is your token:\n{token}')

                    #If there's a token, insert into db with all user value inside (So we can create the account after verifying 2fa in other route)
                    if token:


                        execute_commit('INSERT INTO verification_token (token, account_id, username, hashed_pass, school_email, school) VALUES (%s, %s, %s, %s, %s, %s)', (token, -1, username, hashed_password, email, school))
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

                if common_password:
                    email_error = False
                    username_error = False
                    common_password_error = True

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

    return render_template('processes/signup.html', form=form, username_error=username_error, email_error=email_error, signup_status=signup_status, password_error=password_error, common_password_error=common_password_error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if check_login_status():
        return redirect(url_for('home'))


    form=login_form(request.form)

    # Setting error message
    not_logged_in = False
    account_locked = False
    invalid_pass_or_username = False
    account_id = None

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
                            #If login success, Check if account has enabled 2fa
                            account_status_tuple = execute_fetchone('SELECT * FROM account_status WHERE account_id = %s', (account_id,))
                            account_status_2fa = account_status_tuple['enabled_2fa']



                            if account_status_2fa == 'enabled': #if enabled 2FA



                                # Send 2FA token
                                account_tuple = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s', (account_id,))
                                account_email = account_tuple['school_email']
                                account_username = account_tuple['username']
                                generate_token = serializer.dumps(account_email, salt='2fa')
                                _2fa_link = url_for('login_2fa', token=generate_token, _external=True)

                                _2fa_message = Message('Sign-in with 2FA Token', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])

                                _2fa_message.body = f"Dear {account_username},\n\nTo complete your sign-in, please use the following 2FA link:\n{_2fa_link}\n\nThis message is auto generated. Please do not reply."

                                #Set the token in db first
                                execute_commit('INSERT INTO verification_token (token, account_id) VALUES (%s,%s)',(generate_token, account_id))

                                mail.send(_2fa_message)



                                return f'2fa token sent to {account_email}'

                                # Generate message
                                #CONTINUE WHERE YOU LEFT OFF (ACCOUNT LOGIN, 2FA DETECTED, NOW GENERATE MESSAGE AND CREATE approute for confirming)


                            else: #There is no 2FA enabled
                                #If login success, try to create session for the user
                                create_session('login_status', True)
                                create_session('login_id', account_id)
                                create_session('username', username)
                                session.permanent = True

                                #Reset account status
                                sql = 'UPDATE account_status SET failed_attempts = 0 WHERE account_id = %s AND failed_attempts < 5'
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

                elif bcrypt.check_password_hash(hashed_pass, password) == False: # If wrong password
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
                            execute_commit(sql, val) #Lock the user account

                            #Generate a account locking email
                            locking_message = Message(f'Account Locked for Security Safety', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
                            locking_message.body = f'We have notice suspicious multiple failed login attempt from your account.\n\nTo protect your account, we have locked the account. Please contact administrator for support'
                            mail.send(locking_message)


                            print('account with account id of:', account_id, 'has been locked')
                            # account locked
                            account_locked = True
                        elif int(failed_account['failed_attempts']) == 3: # If 3 login failed attempt, generate message to warn user
                            warning_message = Message(f'Suspicious Login Attempt Reported', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
                            warning_message.body = f'We have notice multiple failed login attempt from your account.\n\nIf it is not you, Please reset your password IMMEDIATELY'
                            mail.send(warning_message)


                    else:
                        sql = 'INSERT INTO account_status (account_id, failed_attempts) VALUES (%s, 1)'
                        execute_commit(sql, val)


            # if no result
            invalid_pass_or_username = True



    return render_template('processes/login.html', form=form, account_locked=account_locked, invalid_pass_or_username=invalid_pass_or_username, account_id=account_id)

@app.route('/logout')
def logout():
    remove_session('login_status')
    remove_session('login_id')
    remove_session('username')
    remove_session('admin_status')
    remove_session('superadmin_status')
    return redirect(url_for('home'))


# IMPORTANT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Below two app route is for optional enabling 2fa. I set mandatory 2fa now so i comment out!
# @app.route('/enable_2fa')
# def enable_2fa():
#
#     if check_session('login_status') != False: # If there is a user logged in
#
#         #Check that user have not enable 2fa before
#         account_status_tuple = execute_fetchone('SELECT * FROM account_status WHERE account_id = %s',(session['login_id'],))
#         if account_status_tuple != None: # if there's account status in the table
#             account_2fa_setting = account_status_tuple['enabled_2fa'] # Get the account status (enabled/disabled)
#         else: # If there is no account status, set one and continue
#             execute_commit('INSERT INTO ACCOUNT_STATUS (account_id) VALUES (%s)',(session['login_id'],))
#             account_2fa_setting = 'disabled'
#
#         if account_2fa_setting == 'disabled':
#             # Check if there's no enable_2fa token in the verification table within 2hr
#             verification_tuple = execute_fetchone(
#                 'SELECT * FROM verification_token WHERE account_id = %s AND token_type = "enable_2fa" AND timecreated BETWEEN DATE_SUB(NOW(), INTERVAL 2 HOUR) AND NOW()',
#                 (session['login_id'],))
#
#             if verification_tuple == None: #If no 2fa enable token was made
#
#                 #Retrieve email basedon the login_id
#                 email_tuple = execute_fetchone('SELECT school_email FROM accounts WHERE account_id = %s', (session['login_id'],))
#                 email = email_tuple['school_email']
#
#                 #Generate a token
#                 token = serializer.dumps(email, salt='2fa')
#                 print("Token generated for 2FA: ", token)
#
#
#                 #Prepare to send 2fa token message
#                 enable_2fa_message = Message(f'2FA Setting Enable Verification',
#                                              sender='ConnectNYPian@gmail.com',
#                                              recipients=['connectnypian.test.receive@gmail.com'])
#
#                 link = url_for('confirm_2fa', token=token, _external=True)
#                 enable_2fa_message.body = f'You have made a request to enable 2 Factor Authentication. To enable, verify please click the link below. Expire in 5 minutes.\n\n{link}\n\nIf you did not make this request, please change your password IMMEDIATELY or contact an administrator.'
#                 mail.send(enable_2fa_message)
#
#                 #After sending the token set the verification token in the DB indicate that a token has been requested
#                 execute_commit('INSERT INTO verification_token (token, account_id, token_type) VALUES (%s,%s,%s)', (token,session['login_id'], 'enable_2fa'))
#
#                 return '2FA token is sent to email'
#
#
#             else:
#                 return 'already made an request. Try again later.'
#         else:
#             return 'account already enabled 2fa'
#     else:
#         return redirect(url_for('signup'))
#
# @app.route('/confirm_2fa/<token>') #This app route is to active 2fa
# def confirm_2fa(token):
#     try:
#         serialized = serializer.loads(token, salt='2fa', max_age=300)
#     except BadSignature:
#         return ' brother this one bad signature'
#     except SignatureExpired:
#         return ' brother next time verify faster'
#     else:
#         token_detail = execute_fetchone('SELECT * FROM verification_token WHERE token = %s',(token,))
#
#         #Check if token is used, if note used, we continue
#         if token_detail['used_boolean'] == False:
#
#             #Set the token to used
#             execute_commit('UPDATE verification_token SET used_boolean = True WHERE token = %s', (token,))
#
#             #Get the account_id
#             account_id = token_detail['account_id']
#
#             #Enable 2fa
#             execute_commit('UPDATE account_status SET enabled_2fa = "enabled" WHERE account_id = %s',(account_id,))
#
#             return '2FA has been successfully activated'
#
#
#         else:
#             return 'eh stop using the same token again, limpeh tell u this token used already right!'

@app.route('/login_2fa/<token>')
def login_2fa(token):
    try:
        serialized = serializer.loads(token, salt='2fa', max_age=300)
    except BadSignature:
        return ' brother this one bad signature'
    except SignatureExpired:
        return ' brother next time verify faster'
    else:
        #Ensure the token is in the db first
        token_tuple = execute_fetchone('SELECT * FROM verification_token WHERE token = %s', (token,))

        #If token exist
        if token_tuple != None:

            #Check that token is not used
            if token_tuple['used_boolean'] != True:

                #Set the token = used
                execute_commit('UPDATE verification_token SET used_boolean = True WHERE token = %s', (token,))

                #Enable sign in
                account_id = token_tuple['account_id']

                #Create session
                session['login_status'] = True
                session['login_id'] = account_id
                session['username'] = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s',(account_id,))['username']
                return redirect(url_for('home'))
            else:
                return 'token used'


        else:
            return 'Token does not exist'



@app.route('/send_reset_pass', methods=['POST','GET'])
def send_reset_pass():
    #This function i made it so that both logged user dont need to key in any form
    form = send_reset_pass_form(request.form)
    if (request.method == 'POST' and form.validate()) or check_login_status(): # If reset password form is submitted
        try:

            if (request.method == 'POST' and form.validate()):
                email = request.form['email']
                user_id_tuple = execute_fetchone('SELECT account_id FROM accounts WHERE school_email = %s',(email,))
            else:
                user_id_tuple = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s',(session['login_id'],))
                email = user_id_tuple['school_email']

        except Error as e:
            return f'Error: {e}'
        else:

            if user_id_tuple != None: #If there's a user from the request reset

                #Set the user_id first
                user_id = user_id_tuple['account_id']

                # Attempt to retrieve all the verification token that user has request today
                all_token = execute_fetchall(
                    'SELECT * FROM verification_token WHERE account_id = %s AND token_type = "reset" AND DATE(timecreated) = CURDATE()',
                    (user_id,))

                # Check if account is locked already
                account_tuple = execute_fetchone('SELECT * FROM account_status WHERE account_id = %s', (user_id,))
                if account_tuple != None:
                    account_locked_status = account_tuple['locked_status'] # 'locked' or 'unlocked'
                else:
                    #if there's no account_status in the db, make one and assign unlocked
                    execute_commit('INSERT INTO account_status (account_id,failed_attempts) VALUES (%s,0)', (user_id,))
                    account_locked_status = 'unlocked'

                if account_locked_status == 'unlocked': #If the account is not locked, allow changing of password
                    #if user request less than 2 reset token, allow new token to be sent
                    if len(all_token) < 2:

                        #make token
                        token = serializer.dumps(email, salt='reset')

                        #prepare message
                        message = Message(f'Reset Password', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
                        verification_link = url_for('reset_pass_confirmed', token=token, _external=True)
                        message.body = f'Here is your reset Link\n\n{verification_link}\n\nVerification link will expire in 5 minutes.'
                        #send message
                        mail.send(message)

                        # note down that user has created a reset request
                        execute_commit('INSERT INTO verification_token (TOKEN, account_id, token_type) VALUES (%s, %s, %s)', (token, user_id, 'reset'))
                        return f'reset link send to {email}'

                    else: #If token exceed 2

                        # send last token and label it as sus_reset (suspicious reset)

                        #try to see if there's already a suspicious reset
                        sus_id_tuple = execute_fetchone('SELECT * FROM verification_token WHERE account_id = %s AND token_type = "sus_reset" and date(timecreated) = CURDATE()', (user_id,))
                        print(sus_id_tuple)
                        if sus_id_tuple == None: # if no suspicious reset token, send a token

                            #Set up warning token and send
                            warning_token = serializer.dumps(email, salt='reset')
                            warning_verification_link = url_for('reset_pass_confirmed', token=warning_token, _external=True)
                            warning_message = Message(f'Suspicious Password Reset Reported', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
                            warning_message.body = f'We have notice suspicious password request from your account.\n\n If it is not you, Please reset your password IMMEDIATELY \n{warning_verification_link}\n\n'
                            mail.send(warning_message)

                            #note down that sus link is sent
                            execute_commit('INSERT INTO verification_token (TOKEN, account_id, token_type) VALUES (%s, %s, %s)',
                                           (warning_token, user_id, 'sus_reset'))


                            return 'sus_link send'

                        else: #if there is already a sus token and the user request again, lock the account.

                            locking_message = Message(f'Account Locked for Security Safety', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
                            locking_message.body = f'We have notice suspicious password request from your account.\n\n To protect your account, we have locked the account. Please contact administrator for support'
                            mail.send(locking_message)

                            #Lock account
                            execute_commit('UPDATE account_status SET locked_status = "locked" WHERE account_id = %s',(user_id,))

                            #clear session
                            remove_session('login_status')
                            remove_session('login_id')
                            remove_session('username')

                            return 'LOCKING UR ACCOUNT AND SEND EMAIL'
                else:
                    return 'account locked please contact admin'



            else:
                #If there's no user, fake send for security reason
                return f'Reset link sent to {email}'
    return render_template('/processes/send_reset_pass.html', form=form)


@app.route('/reset_pass_confirmed/<token>', methods=['GET','POST'])
def reset_pass_confirmed(token):
    try:
        serialized = serializer.loads(token, salt='reset', max_age=300)
    except SignatureExpired:
        return 'token expired'
    except BadSignature:
        return 'wtf is that token brother'
    else:
        form = reset_pass_form(request.form)

        reset_link = url_for('reset_pass_confirmed', token=token, _external=True)
        print("HIHIH")

        # Check if the token is used
        verification_detail = execute_fetchone('SELECT * FROM verification_token WHERE token = %s', (token,))
        print(verification_detail['used_boolean'], ' -')

        # If token not used
        if verification_detail['used_boolean'] == False:
            if request.method == 'POST' and form.validate():

                # Obtaining USERID from token
                user_id = verification_detail['account_id']

                #Obtaining account status from user id
                account_status = execute_fetchone('SELECT * FROM account_status WHERE account_id = %s',(user_id,))
                locked_status = account_status['locked_status']

                # If account is unlocked
                if locked_status == 'unlocked':

                    # Get password and hash the password
                    password = request.form['password']
                    hashed_pass = bcrypt.generate_password_hash(password)

                    # Update new password
                    sql_query = 'UPDATE accounts SET hashed_pass = %s WHERE account_id = %s'
                    val = (hashed_pass, user_id,)
                    result = execute_commit(sql_query, val)


                    if result:
                        # Set the token status = Used (true)
                        execute_commit('UPDATE verification_token SET used_boolean = True WHERE token = %s', (token,))

                        #If reset pass, delete all session


                        remove_session('login_status')
                        remove_session('login_id')
                        remove_session('username')

                        return 'password updated, please log in again'



                    else:
                        return 'error while updating password'
        else:
            return 'token is used'

        return render_template('/processes/reset_pass.html', form=form, reset_link=reset_link)


@app.route('/createpost', methods=['GET', 'POST'])
@check_security_questions
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
@check_security_questions
def createlike(post_id):
    try:
        if 'login_id' in session and checklike(post_id) == False:
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
@check_security_questions
def removelike(post_id):
    try:
        if 'login_id' in session:
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
@check_security_questions
def deletepost(post_id):
    try:
        if 'login_id' in session:
            try:
                sql = 'SELECT account_id FROM posts WHERE post_id = %s'
                val = (post_id, )
                account_id = execute_fetchone(sql, val)
                print(account_id)
            except Error as e:
                print('Error executing sql:', e)
            else:
                if session['login_id'] == account_id['account_id'] or session['admin_status']:
                    sql = 'DELETE FROM comments WHERE post_id = %s'
                    val = (post_id, )
                    execute_commit(sql, val)
                    sql = 'DELETE FROM likes WHERE post_id = %s'
                    execute_commit(sql, val)
                    sql = 'DELETE FROM report_post WHERE post_id = %s'
                    execute_commit(sql, val)
                    sql = 'DELETE FROM posts WHERE post_id = %s'
                    execute_commit(sql, val)
        return redirect(url_for('home'))

    except Error as e:
        print("Error deleting post: ", e)

@app.route('/comments/<post_id>', methods=['GET', 'POST'])
@check_security_questions
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
            sql = 'SELECT * FROM comments INNER JOIN accounts ON comments.account_id = accounts.account_id WHERE comments.post_id = %s ORDER BY comments.comment_timestamp desc'
            val = (str(post_id), )
            comments = execute_fetchall(sql, val)

            if request.method == 'POST' and form.validate():
                body = form.body.data
                form = create_comment(formdata=None)
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
@check_security_questions
def deletecomment(post_id, comment_id):
    try:
        if 'login_id' in session:
            try:
                sql = 'SELECT account_id FROM comments WHERE comment_id = %s'
                val = (str(comment_id), )
                account_id = execute_fetchone(sql, val)
            except Error as e:
                print('Error executing sql:', e)
            else:
                if session['login_id'] == account_id['account_id'] or session['admin_status']:
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
@check_security_questions
def follow_account(account_id):
    try:
        if 'login_id' in session:
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
@check_security_questions
def unfollow_account(account_id):
    try:
        if 'login_id' in session:
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
@check_security_questions
def block(account_id):
    try:
        if 'login_id' in session:

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
@check_security_questions
def unblock(account_id):
    try:
        if 'login_id' in session:
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
@check_security_questions
def report_post(post_id):
    try:
        if 'login_id' in session:
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

@app.route('/unlock-account/<account_id>', methods=['GET', 'POST'])
def unlock_account(account_id):
    wrong_answer = None
    form = unlock_account_form(request.form)
    sql = 'SELECT * FROM security_questions WHERE account_id = %s'
    val = str(account_id),
    result = execute_fetchone(sql, val)
    qn1 = result['qn1']
    qn1_ans = result['qn1_ans']
    qn2 = result['qn2']
    qn2_ans = result['qn2_ans']
    if request.method == 'POST' and form.validate():
        qn1_given_ans = form.qn1_ans.data
        qn2_given_ans = form.qn2_ans.data
        if qn1_given_ans == qn1_ans and qn2_given_ans == qn2_ans:
            sql = "UPDATE account_status SET locked_status = 'unlocked', failed_attempts = 0 WHERE account_id = %s"
            execute_commit(sql, val)
            return 'Account has been unlocked, return to login page'
        else:
            wrong_answer = True
            return render_template('/processes/unlock_account.html', form=form, qn1=qn1, qn2=qn2, wrong_answer=wrong_answer, account_id=account_id)

    return render_template('/processes/unlock_account.html', form=form, qn1=qn1, qn2=qn2, wrong_answer=wrong_answer, account_id=account_id)

@app.route('/verify-as-educator', methods=['GET', 'POST'])
@check_security_questions
def verify_as_educator():
    request_success = False
    form = verify_as_educator_form(request.form)
    sql = 'SELECT * FROM verify_as_educator_request WHERE account_id = %s'
    val = str(session['login_id']),
    result = execute_fetchall(sql, val)
    if result:
        request_success = True

    if request.method == 'POST' and form.validate():
        employee_id = form.employee_id.data
        department = form.department.data
        sql = 'INSERT INTO verify_as_educator_request (account_id, employee_id, department) VALUES (%s, %s, %s)'
        val = (str(session['login_id']), employee_id, department)
        execute_commit(sql, val)
        request_success = True
    return render_template('/processes/verify_as_educator.html', form=form, request_success=request_success)


@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    form = login_form(request.form)
    account_locked = False
    invalid_pass_or_username = False

    if request.method == 'POST' and form.validate():
        try:
            username = request.form['username']
            password = request.form['password']
            result = execute_fetchone("SELECT * FROM accounts WHERE username = %s AND class = 'administrator'", (username,)) # Getting data from database
        except Error as e:
            print("Unknown error occurred while retrieving user credentials.\n", e)

        if result:
            hashed_pass = result['hashed_pass']
            account_id = result['account_id']
            username = result['username']
            #If able to retrieve, continue
            # Checking if the there's a result from the sql query and checking the value of both hash function
            if bcrypt.check_password_hash(hashed_pass, password):
                if checklockedstatus(account_id) == False:
                    try:
                        create_session('login_status', True)
                        create_session('login_id', account_id)
                        create_session('username', username)
                        create_session('admin_status', True)
                        session.permanent = True

                        #Reset account status
                        sql = 'UPDATE account_status SET failed_attempts = 0 WHERE account_id = %s AND failed_attempts < 5'
                        val = session['login_id'],
                        execute_commit(sql, val)

                    except Error as e:
                        print('Admin Login Failed')
                    else:
                        print('Admin Login Success')
                        return redirect(url_for('admin'))
                else:
                    account_locked = True

            elif bcrypt.check_password_hash(hashed_pass, password) == False:
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

            invalid_pass_or_username = True

    return render_template('/processes/admin_login.html', form=form, account_locked=account_locked, invalid_pass_or_username=invalid_pass_or_username)

@app.route('/superadmin-login', methods=['GET', 'POST'])
def superadmin_login():
    invalid_pass_or_username = False
    form = login_form(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        secret_key = form.password.data
        if username == 'superadmin' and secret_key == admin_secret_key:
            create_session('login_status', True)
            create_session('login_id', -1)
            create_session('username', username)
            create_session('admin_status', True)
            create_session('superadmin_status', True)
            session.permanent = True

            return redirect(url_for('superadmin'))

        else:
            invalid_pass_or_username = True

    return render_template('/processes/superadmin_login.html', form=form, invalid_pass_or_username=invalid_pass_or_username)

@app.route('/admin')
@admin_login_required
def admin():
    locked_accounts = execute_fetchall("SELECT * FROM accounts a INNER JOIN account_status ac ON a.account_id = ac.account_id WHERE ac.locked_status = 'locked'")
    verify_as_educator_requests = execute_fetchall("SELECT * FROM accounts a INNER JOIN verify_as_educator_request v ON a.account_id = v.account_id")
    reported_posts = execute_fetchall("SELECT * FROM posts p INNER JOIN report_post r ON p.post_id = r.post_id INNER JOIN accounts a ON a.account_id = p.account_id ORDER BY r.report_timestamp desc")
    return render_template('processes/admin.html', locked_accounts=locked_accounts, verify_as_educator_requests=verify_as_educator_requests, reported_posts=reported_posts)

@app.route('/superadmin', methods=['GET', 'POST'])
@superadmin_login_required
def superadmin():
    username_unique = None
    email_unique = None
    password_same = None
    valid_privilege_level = None
    admin_creation_success = None

    form = create_admin_form(request.form)
    admin_list = execute_fetchall("SELECT * FROM accounts ac INNER JOIN administrators ad ON ac.account_id = ad.account_id WHERE class = 'administrator' ORDER BY ad.privilege_level desc")
    if request.method == 'POST' and form.validate():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        reenterpassword = form.reenterpassword.data
        privilege_level = form.privilege_level.data
        
        result = execute_fetchall('SELECT * FROM accounts WHERE username = %s', (username, ))
        if result:
            username_unique = False
        else:
            username_unique = True
        result = execute_fetchall('SELECT * FROM accounts WHERE school_email = %s', (email, ))
        if result:
            email_unique = False
        else:
            email_unique = True
        if password == reenterpassword:
            password_same = True
            hashed_pass = bcrypt.generate_password_hash(password)
        else:
            password_same = False
        if int(privilege_level) >= 1 and int(privilege_level) <= 10:
            valid_privilege_level = True
        else: 
            valid_privilege_level = False

        if username_unique and email_unique and password_same and valid_privilege_level:
            sql = 'INSERT INTO accounts (username, school_email, hashed_pass, class) VALUES (%s, %s, %s, %s)'
            val = (username, email, hashed_pass, 'administrator')
            execute_commit(sql, val)
            result = execute_fetchone('SELECT * FROM accounts WHERE username = %s', (username, ))
            account_id = result['account_id']
            sql = 'INSERT INTO administrators (account_id, privilege_level) VALUES (%s, %s)'
            val = (str(account_id), int(privilege_level))
            execute_commit(sql, val)
            admin_creation_success = True
        else:
            admin_creation_success = False

    return render_template('/processes/superadmin.html', form=form, admin_list=admin_list, admin_creation_success=admin_creation_success)

@app.route('/admin-unlock-account/<account_id>')
@admin_login_required
def admin_unlock_account(account_id):
    pass

@app.route('/grant-educator-verification/<account_id>')
@admin_login_required
def grant_educator_verification(account_id):
    pass

if __name__ == '__main__':
    app.run(debug=True)


#Security Issue
#1) account cant be locked if it does not exist
#2) Check database before performing query instead of session
#3) check for no duplicate before allowing sign up.
#4) user still can perform action even after resetting password (because we never keep changing for password change)
