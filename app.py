from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

connect = sqlite3.connect('users.db')
cursor = connect.cursor()

@app.route('/')
def hello_world():  # put application's code here
    return render_template('index.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/contacts')
def contacts():
    return render_template('contacts.html')

@app.route('/pvzadresa')
def pvzadresa():
    return render_template('pvzadresa.html')
@app.route('/test')
def test():
    return render_template('test.html')


if __name__ == '__main__':
    app.run()
