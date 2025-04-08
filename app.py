from flask import Flask,g , render_template, session, request, redirect
import sqlite3

app = Flask(__name__)
app.secret_key = 'fxckbalenci666'

DATABASE = 'users.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/database')
def database():
    db = get_db()
    cursor = db.execute('SELECT * FROM accounts')
    return [dict(row) for row in cursor.fetchall()]

def init_db():
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        'INSERT INTO accounts (username, password) VALUES (?, ?)',
        ("quadeck", "ddd1")
    )
    db.commit()
@app.route('/id/<int:id>')
def get_id(id):
    db = get_db()
    cursor = db.execute('SELECT * FROM accounts WHERE id = ?', (id,))
    user_id = cursor.fetchone()

    if not user_id:
        return render_template('404.html'); print('id не найден')

    return dict(user_id)

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

@app.route('/order')
def order():
    return render_template('order.html')

@app.route('/pickup')
def pickup():
    return render_template('pickup.html')

@app.route('/expose')
def expose():
    return render_template('expose.html')

@app.route('/links')
def links():
    return render_template('links.html')

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run()
