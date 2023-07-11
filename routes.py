from flask import Flask, render_template


app = Flask(__name__)


@app.route("/")
def getNormalRoute():
    return render_template('index.html')


@app.route("/main")
def getIndexRoute():
    return render_template('index.html')


@app.route("/profile")
def getProfileRoute():
    return render_template('profile.html')


@app.route("/login")
def getLoginRoute():
    return render_template('login.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True, port=8000)
