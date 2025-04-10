from flask import Flask,g , render_template, request, redirect, flash, url_for, session, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from io import BytesIO
import logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = 'fxckbalenci666'

app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
PRODUCT_IMAGE_FOLDER = 'static/uploads'

app.config['AVATARS_FOLDER'] = 'static/avatars'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
PRODUCT_AVATARS_FOLDER = 'static/avatars'

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_message = 'Пожалуйста, войдите, чтобы получить доступ к этой странице.'
login_manager.login_view = 'vopros'

class User(UserMixin):
    def __init__(self, id, username, password_hash, role='user'):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.execute('SELECT * FROM accounts WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()

    if user_data:
        role = user_data['role'] if 'role' in user_data else 'user'
        return User(
            id=user_data['id'],
            username=user_data['username'],
            password_hash=user_data['password'],
            role=role
        )
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('vopros'))

        db = get_db()
        user_data = db.execute('SELECT role FROM accounts WHERE id = ?', (current_user.id,)).fetchone()

        if user_data is None or user_data['role'] != 'admin':
            flash('Доступ запрещён!', 'error')
            return redirect(url_for('hello_world'))

        return f(*args, **kwargs)

    return decorated_function

def save_image(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath =   os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filepath
    return None

def save_avatars(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['AVATARS_FOLDER'], filename)
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
@admin_required
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
    if current_user.is_authenticated:
        flash('Вы уже авторизованы!', 'info')
        return redirect(url_for('hello_world'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Все поля обязательны для заполнения!', 'error')
            return render_template('signup.html')

        try:
            db = get_db()
            existing_user = db.execute(
                'SELECT id FROM accounts WHERE username = ?',
                (username,)
            ).fetchone()

            if existing_user:
                flash('Пользователь с таким именем уже существует!', 'error')
                return render_template('signup.html')

            role = 'admin' if username.lower() == 'admin123' else 'user'

            password_hash = generate_password_hash(password)

            default_avatar_path = os.path.join('static', 'images', 'default-avatar.jpg')
            with open(default_avatar_path, 'rb') as f:
                avatar_bytes = f.read()

            db.execute(
                '''INSERT INTO accounts 
                   (username, password, role, avatar) 
                   VALUES (?, ?, ?, ?)''',
                (username, password_hash, role, avatar_bytes)
            )
            db.commit()

            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))

        except sqlite3.Error as e:
            db.rollback()
            flash('Произошла ошибка при регистрации. Попробуйте позже.', 'error')
            app.logger.error(f'Ошибка регистрации: {str(e)}')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('hello_world'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.execute('SELECT * FROM accounts WHERE username = ?', (username,))
        user_data = cursor.fetchone()

        if user_data and check_password_hash(user_data['password'], password):
            user = User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password'])
            login_user(user)

            next_url = session.pop('next', None)
            return redirect(next_url or url_for('hello_world'))
        else:
            flash('Неверный логин или пароль!', 'error')

    return render_template('login.html')

@app.route('/product/<int:articul>')
def product_page(articul):
    db = get_db()
    product = db.execute('SELECT * FROM products WHERE articul = ?', (articul,)).fetchone()

    if product is None:
        flash("Товар не найден", "error")
        return redirect(url_for('catalog'))

    return render_template('product.html', product=product)

@app.route('/add_to_cart/<int:articul>', methods=['POST'])
@login_required
def add_to_cart(articul):
    db = get_db()
    product = db.execute('SELECT * FROM products WHERE articul = ?', (articul,)).fetchone()

    if not product:
        flash("Товар не найден", "error")
        return redirect(url_for('catalog'))

    if 'cart' not in session:
        session['cart'] = []

    session['cart'].append({'articul': articul, 'name': product['name'], 'price': product['price']})

    session.modified = True  #

    flash(f"Товар {product['name']} добавлен в корзину.", "success")
    return redirect(url_for('product_page', articul=articul))

@app.route('/contacts')
def contacts():
    return render_template('contacts.html')

@app.route('/pvzadresa')
def pvzadresa():
    return render_template('pvzadresa.html')

@app.route('/catalog')
@login_required
def catalog():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    db = get_db()

    total_products = db.execute('SELECT COUNT(*) FROM products').fetchone()[0]

    total_pages = (total_products + per_page - 1) // per_page

    products = db.execute(
        'SELECT * FROM products LIMIT ? OFFSET ?',
        (per_page, (page - 1) * per_page)
    ).fetchall()

    return render_template(
        'catalog.html',
        products=products,
        page=page,
        total_pages=total_pages,
        per_page=per_page
    )

@app.route('/pickup')
@login_required
def pickup():
    return render_template('pickup.html')

@app.route('/expose')
@login_required
def expose():
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
@login_required
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

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    user_data = db.execute(
        'SELECT username, created_at FROM accounts WHERE id = ?',
        (current_user.id,)
    ).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        image_file = request.files.get('image')

        if name:
            db.execute(
                'UPDATE accounts SET username = ? WHERE id = ?',
                (name, current_user.id)
            )
            db.commit()

        if image_file:
            image_bytes = image_file.read()
            db.execute(
                'UPDATE accounts SET avatar = ? WHERE id = ?',
                (image_bytes, current_user.id)
            )
            db.commit()

        return redirect(url_for('profile'))

    avatar_url = url_for('user_avatar', user_id=current_user.id)

    return render_template('profile.html', user=user_data, avatar_url=avatar_url)

@app.route('/avatar/<int:user_id>')
def user_avatar(user_id):
    db = get_db()
    row = db.execute(
        'SELECT avatar FROM accounts WHERE id = ?',
        (user_id,)
    ).fetchone()

    if row and row['avatar']:
        return send_file(
            BytesIO(row['avatar']),
            mimetype='image/jpeg,png,jpg,gif'
        )
    else:
        # Отдать заглушку
        return redirect(url_for('static', filename='default_avatar.png'))

@app.route('/vopros')
def vopros():
    if current_user.is_authenticated:
        return redirect(url_for('hello_world'))

    session['next'] = request.args.get('next') or request.referrer
    return render_template('vopros.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
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