from flask import Flask, render_template, request, redirect, url_for, session, app
import mysql.connector
from mysql.connector import Error
from datetime import date, timedelta
from forms import *

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=5)

mydb = mysql.connector.connect(
    host='locathost',
    user='root',
    password='somepassword'
)

mycursor = mydb.cursor()


# EXTERNAL FUNCTIONS

# function for creating a comment, must assign createcomment form to a variable in applicable routes
def createcomment(form, post_id):
    if request.method == 'POST':
        body = form.body.data

        sql = "INSERT INTO comments (body, post_id, acocunt_id) VALUES (%s, %s, %s)"
        val = (body, post_id, session[id])
        mycursor.execute(sql, val)
        mydb.commit()
        print("comment added to database")

    pass

def createlike(post_id):
    if 'id' in session:
        like_date = date.today
        sql = "INSERT INTO like (like_date, post_id, account_id) VALUES (%s, %s, %s)"
        val = (like_date, post_id, session[id])
        mycursor.execute(sql, val)
        mydb.commit()
        print("like added to database")

    pass

# END OF EXTERNAL FUNCTIONS



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
    app.run()
