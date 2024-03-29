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
from flask_talisman import Talisman
import string
import random
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address
import secrets

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

#Default limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5/second"] # 5 per second request only
)




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
        print("Execute commit finish")
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
        print("Execute fetchone finish")
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

def remove_all_session_user():
    try:
        remove_session('login_status')
        remove_session('login_id')
        remove_session('username')
        remove_session('latest_reset_token')
        remove_session('admin_status')
        remove_session('superadmin_status')
    except Exception:
        print("Error in function; remove all session")
    else:
        return True

def remove_all_session_superadmin_or_admin():
    try:
        remove_session('login_status')
        remove_session('login_id')
        remove_session('admin_status')
        remove_session('superadmin_status')
    except Exception:
        print('Error in function; remove all session super or admin')
    else:
        return True

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

                print("super admin!")
                return redirect(url_for('superadmin'))
            elif 'admin_status' in session:
                print('admin!')
                return redirect(url_for('admin'))


            sql = 'SELECT * FROM security_questions WHERE account_id = %s'
            val = str(session['login_id']),
            result = execute_fetchone(sql, val)
            if result:
                pass
            else:
                return redirect(url_for('create_security_questions'))

            return f(*args, **kwargs)
        else:
            return redirect(url_for('signup'))
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


#Generate the superadmin dynamic key
def generate_random_keyword(length):
    print('Generating...')
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for _ in range(length))





common_passwords_list = [] #list of 10k most common passwords
common_passwords = open('10k-most-common.txt', 'r')
for line in common_passwords:
    if containsLetterAndNumber(line):
        common_passwords_list.append(line.rstrip())

common_passwords_list = mergeSort(common_passwords_list)

# DYNAMIC SESSION LIFE
@app.before_request
@limiter.exempt()
def before_request():

    #create_session('login_status',True)
    #create_session('login_id',2)


    print("Before request")
    if check_session('login_status'):# if logged in (Normal user)
        print("Login!")
        session.permanent = True


        # Check if user still exist, if not just log them out (To ensure user id is valid in db)
        user_tuple = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s', (session['login_id'],))
        if user_tuple == None:
            # since superadmin id = -1, it's 100% not in db, so to prevent removing of superadmin session
            if not check_session('superadmin_status'):
                remove_all_session_user()
                remove_all_session_superadmin_or_admin()



        if check_session('admin_status'): # For normal user

            # If it is admin_status or superadmin_status
            app.permanent_session_lifetime = timedelta(minutes=1)  # One minute time out
            print(app.permanent_session_lifetime, ' - session time resetted!')
        else:

            # Dynamic session life_time for inactivity for 5min
            app.permanent_session_lifetime = timedelta(minutes=5)
            print(app.permanent_session_lifetime, ' - session time resetted!')



            # if latest reset token is in session
            reset_token_tuple = execute_fetchone(
                'SELECT * FROM verification_token WHERE token_type = "reset" and account_id = %s AND used_boolean = True ORDER BY timecreated DESC LIMIT 1',
                (session['login_id'],))

            if reset_token_tuple != None:  # If there is latest token
                try:
                    latest_reset_token = session['latest_reset_token']
                except:
                    # If there is no reset token, kick the user out too
                    # Because there is reset_token_tuple in the db
                    print("There is no reset token!")
                    remove_all_session_user()
                else:
                    # IF there is reset token, check the value
                    if latest_reset_token == reset_token_tuple['TOKEN']:
                        print("Reset token is the same! Account is valid")
                    else:
                        print("Account not valid! kIck him out")
                        remove_all_session_user()












#END


@app.errorhandler(404)
@limiter.exempt()
def error_page(e):
    return render_template('/processes/error404.html')

@app.errorhandler(429)
def limiter_error(e):
    return 'Too much request, please try again later.'


@app.route('/')
@check_security_questions
def home():
    print("home!")
    if 'superadmin_status' in session:
        return redirect(url_for('superadmin'))
    elif 'admin_status' in session:
        return redirect(url_for('admin'))

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
        request = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s', (str(session['login_id']), ))
        acc_class = request['class']
        if acc_class == 'student':
            sql = 'SELECT school FROM students WHERE account_id = %s'
            val = str(session['login_id']),
            school = execute_fetchone(sql, val)
            sql = 'SELECT * FROM posts INNER JOIN accounts on posts.account_id = accounts.account_id INNER JOIN students ON posts.account_id = students.account_id WHERE students.school = %s AND posts.account_id NOT IN (SELECT blocked_account_id FROM blocks WHERE blocker_account_id = %s) AND posts.account_id NOT IN (SELECT blocker_account_id FROM blocks WHERE blocked_account_id = %s) ORDER BY posts.post_timestamp desc'
            val = (str(school['school']), str(session['login_id']), str(session['login_id']))
            feed = execute_fetchall(sql, val)
        elif acc_class == 'educator' or 'administrator':
            feed = execute_fetchall('SELECT * FROM posts INNER JOIN accounts on posts.account_id = accounts.account_id INNER JOIN students ON posts.account_id = students.account_id ORDER BY posts.post_timestamp desc')
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
            account_type_tuple = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s AND class != "administrator"',(id,))
            account_type = account_type_tuple['class']




            if account_type == 'student':
                result = execute_fetchone('SELECT * FROM accounts a INNER JOIN students s ON a.account_id = s.account_id WHERE a.account_id = %s', (id,)) #Try to retrieve account id
                school = result['school']
            elif account_type == 'educator':
                result = execute_fetchone('SELECT * FROM accounts a INNER JOIN educators s ON a.account_id = s.account_id WHERE a.account_id = %s',(id,))  # Try to retrieve account id
                school = result['school']

            elif account_type == 'administrator':
                result = execute_fetchone('SELECT * FROM accounts a INNER JOIN administrators s ON a.account_id = s.account_id WHERE a.account_id = %s',(id,))  # Try to retrieve account id
                school = 'under the sea'

            account_id = result['account_id']
            school_email = result['school_email']
            username = result['username']
            created_timestamp = result['created_timestamp']
            account_class = result['class']

            posts = execute_fetchall('SELECT * FROM posts WHERE account_id = %s ORDER BY post_timestamp desc', (id, ))
            following = execute_fetchall('SELECT count(*) following FROM follow_account WHERE follower_id = %s', (id,))
            followers = execute_fetchall('SELECT count(*) followers FROM follow_account WHERE followee_id = %s', (id,))
            post_no = execute_fetchall('SELECT count(*) posts FROM posts WHERE account_id = %s', (id,))
        except Exception: # if error
            return 'No such user page'
            print("error retrieving account id")
            #Redirect to error page
        else: # if able to retrieve
            if result: #If account id exist
                try:

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
@limiter.limit('1/3second')
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
                    pwsalt = token_detail['salt']

                    print(email)

                except Exception as e:
                    pass
                else:

                    try:
                         # Inserting data into account: account_id, email, username, date_created
                        execute_commit('INSERT INTO accounts (salt, hashed_pass, school_email, username, class) VALUES (%s, %s, %s, %s, %s)',(pwsalt, hashed_password, email, username, 'student'))
                        # Inserting school into sub table
                        account_id_tuple = execute_fetchone('SELECT account_id FROM accounts WHERE username = %s', (username, ))
                        account_id = account_id_tuple['account_id']
                        execute_commit('INSERT INTO students (account_id, school) VALUES (%s, %s)', (str(account_id), school))

                    except IntegrityError:

                        #Error in creating account
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
                        session_message = f'{username} created successfully. Please login to continue.'
                        create_session('account_creation', session_message)
                        return redirect(url_for('login'))


    error_message = 'Invalid Sign up Token. Please try again.'
    create_session('invalid_token', error_message)
    return redirect(url_for('login'))




@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'superadmin_status' in session:
        return redirect(url_for('superadmin'))
    elif 'admin_status' in session:
        return redirect(url_for('admin'))


    if check_login_status():
        return redirect(url_for('home'))

    #Declare username/email error/signup_status for error message
    username_error = None
    email_error = None
    signup_status = None
    password_error = None
    common_password_error = None
    rate_limit = False

    form = signup_form(request.form)
    # If there's a POST request(Form submitted) enter statement.
    if request.method == 'POST' and form.validate():
        try:
            with limiter.limit('1/10minute, 10/day'): # Limiter limit 1/10min, 10/day

                print("Signing Up")
                # Try:
                # Retrieve User Credential in the form
                try:
                    username = request.form['username']
                    password = request.form['password']
                    reenterpassword = request.form['reenterpassword']
                    school = form.school.data


                    pwsalt = secrets.token_hex(16)
                    salted_password = password+pwsalt


                    hashed_password = bcrypt.generate_password_hash(salted_password)  # Hash the password




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


                                execute_commit('INSERT INTO verification_token (salt, token, account_id, username, hashed_pass, school_email, school) VALUES (%s, %s, %s, %s, %s, %s, %s)', (pwsalt,token, -1, username, hashed_password, email, school))
                                signup_status = f'An verification token has been sent to {email}, please verify to complete the sign up.'

                                message = Message(f'{email}| Email verification Token', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
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
        except RateLimitExceeded:
            rate_limit = True

    return render_template('processes/signup.html', rate_limit=rate_limit, form=form, username_error=username_error, email_error=email_error, signup_status=signup_status, password_error=password_error, common_password_error=common_password_error)



@app.route('/login', methods=['GET','POST'])
def login():
    print('login route')
    if 'superadmin_status' in session:
        return redirect(url_for('superadmin'))
    elif 'admin_status' in session:
        return redirect(url_for('admin'))

    if check_login_status():
        print('account logged in')
        return redirect(url_for('home'))


    form=login_form(request.form)

    # Setting error message
    not_logged_in = False
    account_locked = False
    invalid_pass_or_username = False
    account_id = None
    rate_limit=False
    _login_token_ = None

    creation_message = None
    if 'account_creation' in session:
        creation_message = session['account_creation']
        remove_session('account_creation')

    invalid_token = None
    if 'invalid_token' in session:
        invalid_token = session['invalid_token']
        remove_session('invalid_token')

    # If there's a POST request(Form submitted) enter statement.
    if request.method == 'POST' and form.validate(): # If a form is submitted
        try:
            print("POSTPOSTPOSTPOST")
            with limiter.limit("1/1second, 5/minute, 20/hour, 50/day"):
                try:
                    print("Retrieving data for login")
                    # Retrieve User Credential in the form
                    username = request.form['username']
                    password = request.form['password']
                    result = execute_fetchone('SELECT * FROM accounts WHERE username = %s AND class != "administrator"', (username,)) # Getting data from database
                except Error as e:

                    print("Unknown error occurred while retrieving user credential.\n", e)
                    return 'error'
                else:

                    # If there's result from retrieving
                    if result:
                        print("Retrieving data")
                        # Assigning value from the data retrieved
                        hashed_pass = result['hashed_pass']
                        salt = result['salt']
                        account_id = result['account_id']
                        username = result['username']

                        password_to_check = password+salt

                        #If able to retrieve, continue
                        # Checking if the there's a result from the sql query and checking the value of both hash function
                        if bcrypt.check_password_hash(hashed_pass, password_to_check):
                            print('PASSWORD IS SAME! AS HASH')
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

                                        _2fa_message = Message(f'{account_email} | Sign-in with 2FA Token', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])

                                        _2fa_message.body = f"Dear {account_username},\n\nTo complete your sign-in, please use the following 2FA link:\n{_2fa_link}\n\nThis message is auto generated. Please do not reply."

                                        #Set the token in db first
                                        execute_commit('INSERT INTO verification_token (token, account_id, token_type) VALUES (%s,%s,%s)',(generate_token, account_id,"2fa"))

                                        mail.send(_2fa_message)



                                        _login_token_ = f'An login token has been sent to {account_email}, please login through the token.'

                                        # Generate message
                                        #CONTINUE WHERE YOU LEFT OFF (ACCOUNT LOGIN, 2FA DETECTED, NOW GENERATE MESSAGE AND CREATE approute for confirming)


                                    else: #There is no 2FA enabled
                                        #If login success, try to create session for the user
                                        create_session('login_status', True)
                                        create_session('login_id', account_id)
                                        create_session('username', username)


                                        #Get the latest reset token if there is any to compare with existing
                                        reset_token_tuple = execute_fetchone(
                                            'SELECT * FROM verification_token WHERE token_type = "reset" and account_id = %s AND used_boolean = True ORDER BY timecreated DESC LIMIT 1',
                                            (account_id,))
                                        if reset_token_tuple != None:
                                            latest_reset_token = reset_token_tuple['TOKEN']
                                            session['latest_reset_token'] = latest_reset_token

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

                                        print("Login success")
                                        return redirect(url_for('home'))

                                except Error as e: #If login fail
                                    return 'login failed'
                                    print("Login Fail")
                                    print("Unknown error occurred while trying to create session for user.\n", e)
                                else:
                                    pass
                            else:
                                #even if correct pass, but locked
                                account_locked = True

                        elif bcrypt.check_password_hash(hashed_pass, password_to_check) == False: # If wrong password
                            print("Wrong password for:", username)
                            sql = 'SELECT * FROM account_status WHERE account_id = %s'

                            val = account_id,

                            account_status = execute_fetchone(sql, val)
                            if account_status:
                                sql = 'UPDATE account_status SET failed_attempts = failed_attempts + 1 WHERE account_id = %s'
                                execute_commit(sql, val)

                                # Get email
                                account_tuple = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s',
                                                                 (account_id,))
                                account_email = account_tuple['school_email']

                                failed_account = execute_fetchone('SELECT failed_attempts FROM account_status WHERE account_id = %s', (account_id,))
                                print(failed_account)
                                if int(failed_account['failed_attempts']) >= 5:

                                    sql = 'UPDATE account_status SET locked_status = %s WHERE account_id = %s'
                                    val = ('locked', account_id)
                                    execute_commit(sql, val) #Lock the user account




                                    #Generate a account locking email
                                    locking_message = Message(f'{account_email} | Account Locked for Security Safety', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
                                    locking_message.body = f'Dear{username},\n\nWe have notice suspicious multiple failed login attempt from your account.\n\nTo protect your account, we have locked the account. Please contact administrator for support'
                                    mail.send(locking_message)


                                    print('account with account id of:', account_id, 'has been locked')
                                    # account locked
                                    account_locked = True
                                elif int(failed_account['failed_attempts']) == 3: # If 3 login failed attempt, generate message to warn user
                                    warning_message = Message(f'{account_email} | Suspicious Login Attempt Reported', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
                                    warning_message.body = f'Dear{username},\n\nWe have notice multiple failed login attempt from your account.\n\nIf it is not you, Please reset your password IMMEDIATELY'
                                    mail.send(warning_message)


                            else:
                                sql = 'INSERT INTO account_status (account_id, failed_attempts) VALUES (%s, 1)'
                                execute_commit(sql, val)


                    # if no result
                    print("No result")
                    invalid_pass_or_username = True
        except RateLimitExceeded:
            rate_limit=True



    return render_template('processes/login.html', _login_token_=_login_token_, invalid_token=invalid_token, creation_message=creation_message, rate_limit=rate_limit, form=form, account_locked=account_locked, invalid_pass_or_username=invalid_pass_or_username, account_id=account_id)

@app.route('/logout')
def logout():
    remove_all_session_user()
    remove_all_session_superadmin_or_admin()
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
@limiter.limit('1/3second')
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


                #Enable sign in
                account_id = token_tuple['account_id']

                #Create session login_status, login_id and username
                session['login_status'] = True
                session['login_id'] = account_id
                session['username'] = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s',(account_id,))['username']

                #fetch the latest reset token and set it in the session if there's one
                reset_token_tuple = execute_fetchone('SELECT * FROM verification_token WHERE token_type = "reset" and account_id = %s AND used_boolean = True ORDER BY timecreated DESC LIMIT 1',(account_id,))
                if reset_token_tuple != None:
                    print(reset_token_tuple)
                    latest_reset_token = reset_token_tuple['TOKEN']
                    session['latest_reset_token'] = latest_reset_token

                # Set the token = used
                execute_commit('UPDATE verification_token SET used_boolean = True WHERE token = %s', (token,))

                return redirect(url_for('home'))
            else:
                return 'token used'


        else:
            return 'Token does not exist'



@app.route('/send_reset_pass', methods=['POST','GET'])
def send_reset_pass():
    #This function i made it so that both logged user dont need to key in any form
    form = send_reset_pass_form(request.form)
    rate_limit, success = False, None

    if (request.method == 'POST' and form.validate()) or check_login_status(): # If reset password form is submitted
        try:
            with limiter.limit('100/5minute, 3/day'):
                try:

                    if not check_login_status(): # If submitting the form
                        email = request.form['email']
                        user_id_tuple = execute_fetchone('SELECT account_id FROM accounts WHERE school_email = %s',(email,))
                    elif not check_session('superadmin_status'): #elif not submitting form and not superadmin_stataus
                        user_id_tuple = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s',(session['login_id'],))
                        email = user_id_tuple['school_email']

                    if check_session('superadmin_status'):
                        return 'superadmin no access to this function'

                except Error as e:
                    print("ERROR OCCURED, SUCCESS = FALSE")
                    success = False
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
                                message = Message(f'{email} | Reset Password', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
                                verification_link = url_for('reset_pass_confirmed', token=token, _external=True)
                                message.body = f'Here is your reset Link\n\n{verification_link}\n\nVerification link will expire in 5 minutes.'
                                #send message
                                mail.send(message)

                                # note down that user has created a reset request
                                execute_commit('INSERT INTO verification_token (TOKEN, account_id, token_type) VALUES (%s, %s, %s)', (token, user_id, 'reset'))

                                print("Token quota still avaliable, SUCCESS TRUE")

                                success_message = f'An reset token has been sent to {email}.'
                                success = success_message


                            else: #If token exceed 2

                                # send last token and label it as sus_reset (suspicious reset)

                                #try to see if there's already a suspicious reset
                                sus_id_tuple = execute_fetchone('SELECT * FROM verification_token WHERE account_id = %s AND token_type = "sus_reset" and date(timecreated) = CURDATE()', (user_id,))
                                print(sus_id_tuple)
                                if sus_id_tuple == None: # if no suspicious reset token, send a token

                                    #Set up warning token and send
                                    warning_token = serializer.dumps(email, salt='reset')
                                    warning_verification_link = url_for('reset_pass_confirmed', token=warning_token, _external=True)
                                    warning_message = Message(f'{email} | Suspicious Password Reset Reported', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
                                    warning_message.body = f'We have notice suspicious password request from your account.\n\n If it is not you, Please reset your password IMMEDIATELY \n{warning_verification_link}\n\n'
                                    mail.send(warning_message)

                                    #note down that sus link is sent
                                    execute_commit('INSERT INTO verification_token (TOKEN, account_id, token_type) VALUES (%s, %s, %s)',
                                                   (warning_token, user_id, 'sus_reset'))


                                else: #if there is already a sus token and the user request again, lock the account.

                                    locking_message = Message(f'{email} | Account Locked for Security Safety', sender='ConnectNYPian@gmail.com', recipients=['connectnypian.test.receive@gmail.com'])
                                    locking_message.body = f'We have notice suspicious password request from your account.\n\n To protect your account, we have locked the account. Please contact administrator for support'
                                    mail.send(locking_message)

                                    #Lock account
                                    execute_commit('UPDATE account_status SET locked_status = "locked" WHERE account_id = %s',(user_id,))

                                    #clear session

                                print("Token exceed 2, SUCCESS FALSE")
                                success = False



                        else:
                            print("ACCOUNT LOCKED, SUCCESS FALSE")
                            success = False
                            remove_all_session_user()



                    else:
                        print("NO SUCH USER, ERROR STILL FALSE")

                        success = False
                        #If there's no user, fake send for security reason
        except RateLimitExceeded:
            rate_limit = True
            print("rate limited")

    return render_template('/processes/send_reset_pass.html',success=success, rate_limit=rate_limit, form=form)


@app.route('/reset_pass_confirmed/<token>', methods=['GET','POST'])
@limiter.limit('1/3second')
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
                    account_tuple = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s',(user_id,))
                    salt = account_tuple['salt']

                    salted_password = password+salt

                    hashed_pass = bcrypt.generate_password_hash(salted_password)

                    # Update new password
                    sql_query = 'UPDATE accounts SET hashed_pass = %s WHERE account_id = %s'
                    val = (hashed_pass, user_id,)
                    result = execute_commit(sql_query, val)


                    if result:
                        # Set the token status = Used (true)
                        execute_commit('UPDATE verification_token SET used_boolean = True WHERE token = %s', (token,))

                        #If reset pass, delete all session on the device


                        remove_all_session_user()

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
    rate_limit = False
    if request.method == 'POST' and form.validate():
        try:
            with limiter.limit("10/minute, 20/hour, 50/day"):
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
        except RateLimitExceeded:
            rate_limit = True

    return render_template('/processes/createpost.html', rate_limit=rate_limit, form=form)

@app.route('/createlike/<int:post_id>/')
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

@app.route('/removelike/<int:post_id>')
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

@app.route('/deletepost/<int:post_id>')
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

@app.route('/comments/<int:post_id>', methods=['GET', 'POST'])
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
                rate_limit = False
                if request.method == 'POST' and form.validate():
                    try:
                        with limiter.limit("10/minute, 50/hour, 10/day"):
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
                    except RateLimitExceeded:
                        rate_limit = True

        return render_template('/processes/comments.html', rate_limit=rate_limit, post=post, liked_posts=liked_posts, form=form, comments=comments)

    except Error as e:
        print('Error creating comment: ', e)

@app.route('/deletecomment/<int:post_id>/<comment_id>')
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

@app.route('/follow/<int:account_id>')
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

@app.route('/unfollow/<int:account_id>')
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

@app.route('/block/<int:account_id>')
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

@app.route('/unblock/<int:account_id>')
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

@app.route('/report-post/<int:post_id>', methods=['GET', 'POST'])
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

@app.route('/unlock-account/<int:account_id>', methods=['GET', 'POST'])
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
    duplicate_employee_id = False
    form = verify_as_educator_form(request.form)
    sql = 'SELECT * FROM verify_as_educator_request WHERE account_id = %s'
    val = str(session['login_id']),
    result = execute_fetchall(sql, val)
    if result:
        request_success = True

    if request.method == 'POST' and form.validate():
        employee_id = form.employee_id.data
        result = execute_fetchall('SELECT * FROM verify_as_educator_request WHERE employee_id = %s', (employee_id, ))
        if result:
            duplicate_employee_id = True
            return render_template('/processes/verify_as_educator.html', form=form, request_success=request_success, duplicate_employee_id=duplicate_employee_id)
        department = form.department.data
        sql = 'INSERT INTO verify_as_educator_request (account_id, employee_id, department) VALUES (%s, %s, %s)'
        val = (str(session['login_id']), employee_id, department)
        execute_commit(sql, val)
        request_success = True
    return render_template('/processes/verify_as_educator.html', form=form, request_success=request_success, duplicate_employee_id=duplicate_employee_id)

@app.route('/delete_account')
def delete_account():
    #Only for normal account, admin can't delete account
    if 'login_status' in session:
        #check if it's a admin account
        if not check_session('superadmin_status') and not check_session('admin_status'):
            #if not admin, delete account using session id
            try:
                id_to_delete = session['login_id']

                #Try to get the class of the account
                account_tuple = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s',(id_to_delete,))
                account_class = account_tuple['class']

            except Exception:
                return 'Error in deleting account'
            else:
                #Delete from security question
                execute_commit('DELETE FROM security_questions WHERE account_id = %s', (id_to_delete,))

                #Delete comment made by user
                execute_commit('DELETE FROM comments WHERE account_id = %s', (id_to_delete,))

                #Delete post made by user
                execute_commit('DELETE FROM posts WHERE account_id = %s', (id_to_delete,))

                #Delete follow list
                execute_commit('DELETE FROM follow_account WHERE follower_id = %s or followee_id = %s', (id_to_delete,id_to_delete,))

                #Delete verification token made by that user
                execute_commit('DELETE FROM verification_token WHERE account_id = %s', (id_to_delete,))

                #Delete From account_status
                execute_commit('DELETE FROM account_status WHERE account_id = %s',(id_to_delete,))

                #Delete from accounts
                execute_commit('DELETE FROM accounts WHERE account_id = %s', (id_to_delete,))

                #Try to delete from educator/student
                if account_class == 'student':
                    execute_commit('DELETE FROM students WHERE account_id = %s', (id_to_delete,))
                else:
                    execute_commit('DELETE FROM educators WHERE account_id = %s', (id_to_delete,))

                #Remove all session
                remove_all_session_user()

                return redirect('signup')

        else:
            if check_session('superadmin_staus'):
                return redirect('superadmin')
            else:
                return redirect('admin')
    else:
        return redirect('signup')



@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if 'superadmin_status' in session:
        return redirect(url_for('superadmin'))
    elif 'admin_status' in session:
        return redirect(url_for('admin'))

    # Auto clear session
    remove_all_session_user()

    form = login_form(request.form)
    account_locked = False
    invalid_pass_or_username = False
    rate_limit = False

    if request.method == 'POST' and form.validate():
        try:
            with limiter.limit('1/1second, 5/minute, 20/hr, 50/day'):
                try:
                    username = request.form['username']
                    password = request.form['password']
                    result = execute_fetchone("SELECT * FROM accounts WHERE username = %s AND class = 'administrator'", (username,)) # Getting data from database
                    pwsalt = result['salt']
                    pw_to_compare = password+pwsalt
                except Error as e:
                    print("Unknown error occurred while retrieving user credentials.\n", e)

                if result:


                    hashed_pass = result['hashed_pass']
                    account_id = result['account_id']
                    username = result['username']
                    #If able to retrieve, continue
                    # Checking if the there's a result from the sql query and checking the value of both hash function
                    if bcrypt.check_password_hash(hashed_pass, pw_to_compare):
                        if checklockedstatus(account_id) == False:
                            try:

                                # Send 2FA token
                                account_tuple = execute_fetchone('SELECT * FROM accounts WHERE account_id = %s', (account_id,))
                                account_email = account_tuple['school_email']
                                account_username = account_tuple['username']
                                generate_token = serializer.dumps(account_email, salt='2fa')
                                _2fa_link = url_for('admin_login_2fa', token=generate_token, _external=True)

                                _2fa_message = Message(f'Admin: {account_username} | Sign-in with 2FA Token', sender='ConnectNYPian@gmail.com',
                                                       recipients=['connectnypian.test.receive@gmail.com'])

                                _2fa_message.body = f"Dear {account_username},\n\nTo complete your sign-in as Administrator, please use the following 2FA link:\n{_2fa_link}\n\nThis message is auto generated. Please do not reply."

                                # Set the token in db first
                                execute_commit('INSERT INTO verification_token (token, account_id, token_type) VALUES (%s,%s,"2fa")',
                                               (generate_token, account_id))

                                mail.send(_2fa_message)

                                return f'2fa token sent to {account_email}'



                            except Error as e:
                                print('Admin Login Failed')
                            else:
                                print('Admin Login Success')
                                return redirect(url_for('admin'))
                        else:
                            account_locked = True

                    elif bcrypt.check_password_hash(hashed_pass, pw_to_compare) == False:
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
        except RateLimitExceeded:
            rate_limit = True

    return render_template('/processes/admin_login.html', rate_limit=rate_limit, form=form, account_locked=account_locked, invalid_pass_or_username=invalid_pass_or_username)

@app.route('/admin_login_2fa/<token>')
@limiter.limit('1/3second')
def admin_login_2fa(token):
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


                #Enable sign in
                account_id = token_tuple['account_id']


                remove_all_session_user()

                create_session('login_status', True)
                create_session('login_id', account_id)
                create_session('admin_status', True)

                #Reset account status
                sql = 'UPDATE account_status SET failed_attempts = 0 WHERE account_id = %s AND failed_attempts < 5'
                val = session['login_id'],
                execute_commit(sql, val)


                #fetch the latest reset token and set it in the session if there's one
                reset_token_tuple = execute_fetchone('SELECT * FROM verification_token WHERE token_type = "reset" and account_id = %s AND used_boolean = True ORDER BY timecreated DESC LIMIT 1',(account_id,))
                if reset_token_tuple != None:
                    print(reset_token_tuple)
                    latest_reset_token = reset_token_tuple['TOKEN']
                    session['latest_reset_token'] = latest_reset_token

                # Set the token = used
                execute_commit('UPDATE verification_token SET used_boolean = True WHERE token = %s', (token,))

                return redirect(url_for('admin'))
            else:
                return 'token used'

@app.route('/superadmin-login', methods=['GET', 'POST'])
def superadmin_login():


    if 'superadmin_status' in session:
        return redirect(url_for('superadmin'))
    elif 'admin_status' in session:
        return redirect(url_for('admin'))

    # Auto clear session
    remove_all_session_user()


    invalid_pass_or_username = False
    form = login_form(request.form)
    rate_limit=None
    if request.method == 'POST' and form.validate():
        try:
            with limiter.limit('1/minute, 5/hour, 10/day'):
                username = form.username.data
                secret_key = form.password.data
                if username == 'superadmin' and secret_key == execute_fetchone('SELECT * FROM superadmin_key')['superadmin_key']:

                    # Remove all normal user session
                    remove_all_session_user()

                    create_session('login_status', True)
                    create_session('login_id', -1)
                    #create_session('username', username) No need for username
                    create_session('admin_status', True)
                    create_session('superadmin_status', True)

                    print("IM ON SIGNIN SUPPERADMIN- ", session['admin_status'])

                    print("Everything created")

                    return redirect(url_for('superadmin'))

                else:
                    invalid_pass_or_username = True
        except RateLimitExceeded:
            rate_limit=True

    return render_template('/processes/superadmin_login.html', rate_limit=rate_limit, form=form, invalid_pass_or_username=invalid_pass_or_username)

@app.route('/admin')
@admin_login_required
def admin():
    locked_accounts = execute_fetchall("SELECT * FROM accounts a INNER JOIN account_status ac ON a.account_id = ac.account_id WHERE ac.locked_status = 'locked'")
    verify_as_educator_requests = execute_fetchall("SELECT * FROM accounts a INNER JOIN verify_as_educator_request v ON a.account_id = v.account_id")
    reported_posts = execute_fetchall("SELECT * FROM posts p INNER JOIN report_post r ON p.post_id = r.post_id INNER JOIN accounts a ON a.account_id = p.account_id ORDER BY r.report_timestamp desc")

    hide_reset = False
    if check_session('superadmin_status'):
        hide_reset = True
    return render_template('processes/admin.html', hide_reset=hide_reset, locked_accounts=locked_accounts, verify_as_educator_requests=verify_as_educator_requests, reported_posts=reported_posts)

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

            pwsalt = secrets.token_hex(16)# make salt
            salted_password = password+pwsalt
            hashed_pass = bcrypt.generate_password_hash(salted_password)
        else:
            password_same = False
        if int(privilege_level) >= 1 and int(privilege_level) <= 10:
            valid_privilege_level = True
        else:
            valid_privilege_level = False

        if username_unique and email_unique and password_same and valid_privilege_level:
            sql = 'INSERT INTO accounts (salt, username, school_email, hashed_pass, class) VALUES (%s, %s, %s, %s, %s)'
            val = (pwsalt, username, email, hashed_pass, 'administrator')
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

@app.route('/admin-unlock-account/<int:account_id>')
@admin_login_required
def admin_unlock_account(account_id):
    execute_commit("UPDATE account_status SET locked_status ='unlocked', failed_attempts=0 WHERE account_id = %s", (str(account_id), ))
    return redirect(url_for('admin'))

@app.route('/grant-educator-verification/<account_id>')
@admin_login_required
def grant_educator_verification(account_id):
    request = execute_fetchone("SELECT * FROM verify_as_educator_request v INNER JOIN students s ON v.account_id = s.account_id WHERE v.account_id = %s", (str(account_id), ))
    employee_id = request['employee_id']
    department = request['department']
    school = request['school']
    execute_commit('DELETE FROM students WHERE account_id = %s', (str(account_id), ))
    execute_commit('INSERT INTO educators (account_id, employee_id, school, department) VALUES (%s, %s, %s, %s)', (str(account_id), employee_id, school, department))
    execute_commit("UPDATE accounts SET class='educator' WHERE account_id = %s", (str(account_id), ))
    execute_commit('DELETE FROM verify_as_educator_request WHERE account_id = %s', (str(account_id), ))
    return redirect(url_for('admin'))


#Ensure all connection are https
Talisman(app, content_security_policy=None)


#Enable tasked scheduler
def update_superadmin_sql():
    # try:
    #     print("Entered function")
    #     print(execute_fetchone('SELECT * FROM accounts WHERE account_id = "1"'))
    #     print("ExecutedFetchone")
    #     generated_keyword = generate_random_keyword(50)
    #     print('Dynamic key:', generated_keyword)
    #     sql = 'DELETE FROM superadmin_key'
    #     execute_commit(sql,(None,))
    #     execute_commit('INSERT INTO superadmin_key (superadmin_key) VALUES (%s)', (generated_keyword, ))
    #     print('Updated SuperAdmin Key on', datetime.datetime.now())
    # except Exception as e:
    #     print(e)
    pass

# END OF EXTERNAL FUNCTIONS


# scheduler = BackgroundScheduler()
# scheduler.add_job(update_superadmin_sql, 'interval', seconds=2, id='do_job_1')
# scheduler.start()


#MESSAGING PART NOT WOKRING

#    @app.route('/contacts')
#    def contacts():
#        followed_users = execute_fetchall("SELECT * FROM follow_account f INNER JOIN accounts a on f.followee_id = a.account_id WHERE f.follower_id = %s ORDER BY f.followed_timestamp DESC", (str(session['login_id'], )))
#        print(followed_users)
#        return render_template('contacts.html', followed_users=followed_users)
#    
#    
#    
#    #CHAT ROOMS
#    @app.route('/messages', methods=['GET', 'POST'])
#    def messages():
#        try:
#            if 'login_id' not in session:
#                return redirect(url_for('login'))
#    
#            if 'login_id' in session:
#                form = send_message(request.form)
#                execute_commit('SELECT chat_id FROM messages')
#                sql = 'SELECT * FROM messages INNER JOIN accounts ON messages.account_id = accounts.account_id WHERE messages.chat_id = %s ORDER BY messages.sent_timestamp desc'
#                val = (str(chat_id),)
#                chatinfo = execute_fetchone(sql,val)
#                if request.method == 'POST' and form.validate():
#                    body = form.body.data
#                    form = send_message(formdata=None)
#                    execute_commit("INSERT INTO messages (body, account_id, chat_id) VALUES (%s, %s, %s)",(body, sender_account_id, chat_id))
#                    # Fetch and display messages from the database
#                    chatinfo = execute_fetchall("SELECT * FROM accounts ON messages.account_id = accounts.account_id WHERE messages.chat_id = %s ORDER BY messages.sent_timestamp desc",(str(chat_id),))
#                    return render_template('messages.html', chatinfo=chatinfo, form=form, messages=messages)
#    
#            return render_template('messages.html', messages=messages, form=form, chatinfo=chatinfo)
#        except Error as e:
#            print('Error sending message: ', e)




if __name__ == '__main__':
    app.run(debug=True, port=443, ssl_context=('cert.pem', 'key.pem'))


#Security Issue
#1) account cant be locked if it does not exist
#2) Check database before performing query instead of session (FIXED!)
#3) check for no duplicate before allowing sign up. (Fixed!)
#4) user still can perform action even after resetting password (because we never keep changing for password change) (FIXED!)
#5) i dont think educators or admins can post i havent tested
#6) FIXED INVALID USERNAME OR PASSWORD PROMPT
