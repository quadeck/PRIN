from flask import Flask,g , render_template, request, redirect, flash, url_for, session, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from io import BytesIO
import logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = 'fxckbalenci666'

DATABASE = 'users.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
PRODUCT_IMAGE_FOLDER = 'static/uploads'

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

    seller = db.execute('SELECT username FROM accounts WHERE id = ?', (product['user_id'],)).fetchone()
    seller_name = seller['username'] if seller else 'Неизвестный'

    return render_template('product.html', product=product, seller_name=seller_name)

@app.route('/add_to_basket/<int:articul>', methods=['POST'])
@login_required
def add_to_basket(articul):
    db = get_db()
    user_id = current_user.id
    product = db.execute('SELECT * FROM products WHERE articul = ?', (articul,)).fetchone()

    if not product:
        flash("Товар не найден", "error")
        return redirect(url_for('catalog'))

    existing = db.execute(
        'SELECT * FROM cart_items WHERE user_id = ? AND product_articul = ?',
        (user_id, articul)
    ).fetchone()

    if existing:
        db.execute(
            'UPDATE cart_items SET quantity = quantity + 1 WHERE id = ?',
            (existing['id'],)
        )
    else:
        db.execute(
            'INSERT INTO cart_items (user_id, product_articul, quantity) VALUES (?, ?, 1)',
            (user_id, articul)
        )
    db.commit()
    flash(f"Товар {product['name']} добавлен в корзину.", "success")
    return redirect(url_for('product_page', articul=articul))

@app.route('/add_product', methods=['POST'])
@login_required
def add_product():
    name = request.form['name']
    description = request.form['description']
    price = float(request.form['price'])
    stock_quantity = int(request.form['stock_quantity'])

    image_file = request.files.get('image')
    image_url = None

    if image_file and image_file.filename != '':
        if allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(filepath)
            image_url = '/static/uploads/' + filename
        else:
            flash('Недопустимый формат изображения', 'error')
            return redirect(url_for('expose'))

    db = get_db()
    db.execute('''
        INSERT INTO products (name, description, price, stock_quantity, image_url, user_id)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (name, description, price, stock_quantity, image_url, current_user.id))
    db.commit()

    flash('Товар успешно добавлен!', 'success')
    return redirect(url_for('catalog'))

@app.route('/contacts')
def contacts():
    return render_template('contacts.html')

@app.route('/pvzadresa')
def pvzadresa():
    return render_template('pvzadresa.html')

@app.route('/remove_from_basket', methods=['POST'])
@login_required
def remove_from_basket():
    basket_item_id = request.form.get('basket_item_id')
    db = get_db()

    if basket_item_id:
        db.execute('DELETE FROM cart_items WHERE id = ? AND user_id = ?', (basket_item_id, current_user.id))
        db.commit()
        flash("Товар удалён из корзины.", "success")
    else:
        flash("Товар не найден в корзине.", "error")

    return redirect(url_for('basket'))

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

    products_with_seller = []
    for product in products:
        user_id = product['user_id']

        seller = db.execute(
            'SELECT * FROM accounts WHERE id = ?',
            (user_id,)
        ).fetchone()

        seller_name = seller['username'] if seller else 'Неизвестный'

        product_dict = dict(product)
        product_dict['seller_name'] = seller_name

        products_with_seller.append(product_dict)

    return render_template(
        'catalog.html',
        products=products_with_seller,
        page=page,
        total_pages=total_pages,
        per_page=per_page
    )

@app.route('/pickup')
@login_required
def pickup():
    return render_template('pickup.html')

@app.route('/profile/basket', methods=['GET', 'POST'])
@login_required
def basket():
    db = get_db()
    user_id = current_user.id

    basket_items = db.execute(''' 
        SELECT ci.id, ci.quantity, p.articul, p.name, p.price, p.image_url
        FROM cart_items ci
        JOIN products p ON ci.product_articul = p.articul
        WHERE ci.user_id = ?
    ''', (user_id,)).fetchall()

    total_price = sum(item['price'] * item['quantity'] for item in basket_items)

    if request.method == 'POST':
        product_id = request.form.get('product_id')
        db.execute('DELETE FROM cart_items WHERE id = ?', (product_id,))
        db.commit()

        flash('Товар удалён из корзины.', 'success')
        return redirect(url_for('basket'))

    return render_template('basket.html', basket_items=basket_items, total_price=total_price)

@app.route('/expose', methods=['GET', 'POST'])
@login_required
def expose():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        stock_quantity = request.form.get('stock_quantity')

        if not all([name, price, stock_quantity]):
            flash("Пожалуйста, заполните все обязательные поля.", "error")
            return redirect(url_for('expose'))

        image = request.files.get('image')
        image_url = None

        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)
            image_url = '/static/uploads/' + filename
        else:
            flash("Неверный формат изображения.", "error")
            return redirect(url_for('expose'))

        try:
            db = get_db()
            db.execute('''
                INSERT INTO products (name, description, price, stock_quantity, image_url, user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, description, float(price), int(stock_quantity), image_url, current_user.id))
            db.commit()

            flash("Товар успешно добавлен!", "success")
            return redirect(url_for('catalog'))
        except Exception as e:
            db.rollback()
            app.logger.error(f"Ошибка при добавлении товара: {e}")
            flash("Ошибка при добавлении товара.", "error")
            return redirect(url_for('expose'))

    return render_template('expose.html')

@app.route('/update_quantity', methods=['POST'])
@login_required
def update_quantity():
    data = request.get_json()
    item_id = data.get('basket_item_id')
    quantity = data.get('quantity')

    try:
        quantity = int(quantity)
        if quantity < 1:
            raise ValueError("Quantity must be at least 1")
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Неверное количество'})

    db = get_db()
    db.execute(
        'UPDATE cart_items SET quantity = ? WHERE id = ? AND user_id = ?',
        (quantity, item_id, current_user.id)
    )
    db.commit()

    return jsonify({'success': True})

@app.route('/links')
def links():
    return render_template('links.html')

@app.route('/profile/products')
@login_required
def my_products():
    db = get_db()
    user_id = current_user.id

    products = db.execute('''
        SELECT * FROM products WHERE user_id = ?
    ''', (user_id,)).fetchall()
    return render_template('myproducts.html', products=products)

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
        if product['image_url']:
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

@app.route('/order', methods=['GET', 'POST'])
@login_required
def order():
    db = get_db()
    user_id = current_user.id
    basket_items = db.execute('''
        SELECT ci.id, ci.quantity, p.articul, p.name, p.price, p.image_url
        FROM cart_items ci
        JOIN products p ON ci.product_articul = p.articul
        WHERE ci.user_id = ?
    ''', (user_id,)).fetchall()

    total_price = sum(item['price'] * item['quantity'] for item in basket_items)
    message = None

    if request.method == 'POST':
        pickup_point = request.form.get('pickup_point')

        if pickup_point and basket_items:
            try:
                last_order = db.execute('''
                    SELECT MAX(order_number) AS last_order_number 
                    FROM orders 
                    WHERE user_id = ?
                ''', (user_id,)).fetchone()

                order_number = (last_order['last_order_number'] or 0) + 1

                for item in basket_items:
                    product = db.execute('''
                        SELECT stock_quantity FROM products WHERE articul = ?
                    ''', (item['articul'],)).fetchone()

                    if product is None:
                        message = f"Товар с артикулом {item['articul']} не найден."
                        return render_template('order.html', basket_items=basket_items, total_price=total_price,
                                               message=message)

                    if product['stock_quantity'] < item['quantity']:
                        message = f"Недостаточно товара с артикулом {item['articul']} на складе."
                        return render_template('order.html', basket_items=basket_items, total_price=total_price,
                                               message=message)

                created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                db.execute('''
                    INSERT INTO orders (user_id, pickup_point, total_price, created_at, order_number)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, pickup_point, total_price, created_at, order_number))
                db.commit()

                order_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]

                for item in basket_items:
                    db.execute('''
                        INSERT INTO order_items (order_id, product_articul, quantity, price)
                        VALUES (?, ?, ?, ?)
                    ''', (order_id, item['articul'], item['quantity'], item['price']))

                    db.execute('''
                        UPDATE products
                        SET stock_quantity = stock_quantity - ?
                        WHERE articul = ?
                    ''', (item['quantity'], item['articul']))

                db.commit()
                db.execute('DELETE FROM cart_items WHERE user_id = ?', (user_id,))
                db.commit()

                message = "Заказ успешно оформлен!"
                return redirect(url_for('order_history'))

            except Exception as e:
                db.rollback()
                app.logger.error(f"Ошибка при оформлении заказа: {e}")
                message = "Ошибка при оформлении заказа."

        else:
            message = "Пожалуйста, выберите пункт самовывоза."

    return render_template('order.html', basket_items=basket_items, total_price=total_price, message=message)

@app.route('/profile/order_history')
@login_required
def order_history():
    db = get_db()
    user_id = current_user.id

    orders = db.execute('''
        SELECT o.id, o.order_number, o.pickup_point, o.total_price, o.created_at
        FROM orders o
        WHERE o.user_id = ?
        ORDER BY o.created_at DESC
    ''', (user_id,)).fetchall()

    orders_with_items = []
    for order in orders:
        order_items = db.execute('''
            SELECT oi.product_articul, oi.quantity, oi.price, p.name
            FROM order_items oi
            JOIN products p ON oi.product_articul = p.articul
            WHERE oi.order_id = ?
        ''', (order['id'],)).fetchall()

        orders_with_items.append({
            'order': order,
            'items': order_items
        })

    return render_template('order_history.html', order_info=orders_with_items)

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run()