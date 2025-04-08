from flask import Flask,g , render_template, session, request, redirect, flash, url_for
import sqlite3

app = Flask(__name__)
app.secret_key = 'fxckbalenci666'

def init_db():
    connection = sqlite3.connect('users.db')
    cursor = connection.cursor()
    connection.commit()
    connection.close()

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

@app.route('/')
def hello_world():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user' in session:
        return redirect(url_for('hello_world'))
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.execute('SELECT * FROM accounts WHERE username = ?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Пользователь с таким логином уже существует!', 'error')
        else:
            db.execute('INSERT INTO accounts (username, password) VALUES (?, ?)', (username, password))
            db.commit()
            flash('Регистрация прошла успешно! Через 3 секунды вас перенаправят на страницу авторизации', 'success')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()
    error = None
    if 'user' in session:
        return redirect(url_for('hello_world'))

    if request.method == 'GET':
        ref = request.referrer
        if ref and not ref.endswith('/login'):
            session['previous_url'] = ref

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor = db.execute('SELECT * FROM accounts WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()

        if user:
            session['user'] = dict(user)
            return redirect('/')
        else:
            flash('Неверный логин или пароль!', 'errorlog')

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

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('vopros'))

    return render_template('profile.html')

@app.route('/vopros')
def vopros():
    if 'user' in session:
        return redirect(url_for('hello_world'))
    return render_template('vopros.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(request.referrer)

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run()