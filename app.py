from flask import Flask,g , render_template, session, request, redirect, flash, url_for, jsonify
import sqlite3
import os
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = 'fxckbalenci666'

app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
PRODUCT_IMAGE_FOLDER = 'static/uploads'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_image(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath =   os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filepath
    return None

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
    accounts_cursor = db.execute('SELECT * FROM accounts')
    products_cursor = db.execute('SELECT * FROM products')
    accounts = [dict(row) for row in accounts_cursor.fetchall()]
    products = [dict(row) for row in products_cursor.fetchall()]
    return render_template('database.html', accounts=accounts, products=products)

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

@app.route('/catalog')
def catalog():
    if 'user' not in session:
        return redirect(url_for('vopros'))
    db = get_db()
    products_cursor = db.execute('SELECT * FROM products')
    products = [dict(row) for row in products_cursor.fetchall()]

    return render_template('catalog.html', products=products)

@app.route('/pickup')
def pickup():
    if ('user' not in session):
        return redirect(url_for('vopros'))
    return render_template('pickup.html')

@app.route('/expose')
def expose():
    if ('user' not in session):
        return redirect(url_for('vopros'))
    error = None
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        stock_quantity = request.form['stock_quantity']
        db = get_db()
        db.execute('INSERT INTO products (name, description, price, stock_quantity) VALUES (?, ?, ?, ?)', (name, description, price, stock_quantity))
        db.commit()

    return render_template('expose.html')


@app.route('/add_product', methods=['POST'])
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        stock_quantity = int(request.form['stock_quantity'])

        image_file = request.files.get('image')
        image_url = None
        if image_file:
            image_path = save_image(image_file)
            if image_path:
                image_url = '/static/uploads/' + os.path.basename(image_path)
            else:
                flash('Не удалось загрузить файл изображения!', 'errorload')
                return redirect(url_for('add_product'))

        db = get_db()
        db.execute('INSERT INTO products (name, description, price, stock_quantity, image_url) VALUES (?, ?, ?, ?, ?)',
                   (name, description, price, stock_quantity, image_url))
        db.commit()

        flash('Продукт успешно добавлен!', 'successadd')
        return redirect(url_for('catalog'))

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


@app.route('/delete_product', methods=['POST'])
def delete_product():
    articul = request.form['articul']
    db = get_db()

    product = db.execute('SELECT * FROM products WHERE articul = ?', (articul,)).fetchone()

    if product:
        image_name = product['image_url'].split('/')[-1]

        image_path = os.path.join(PRODUCT_IMAGE_FOLDER, image_name)

        if os.path.exists(image_path):
            os.remove(image_path)

        db.execute('DELETE FROM products WHERE articul = ?', (articul,))
        db.commit()

        flash('Товар и изображение успешно удалены.', 'successdel')
    else:
        flash('Товар с таким артикулом не найден.', 'errorsearch')

    return redirect(request.referrer)


@app.route('/delete_account', methods=['POST'])
def delete_account():
    id = request.form['id']
    db = get_db()
    account = db.execute('SELECT * FROM accounts WHERE id = ?', (id,)).fetchone()

    if account:
        db.execute('DELETE FROM accounts WHERE id = ?', (id,))
        db.commit()

    return redirect(request.referrer)

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run()