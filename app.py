# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from functools import wraps
from PIL import Image

from models import db, User, Product
from config import Config

# Image settings
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'webp'}
IMG_WIDTH = 800
IMG_HEIGHT = 800

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Upload folder inside static
    UPLOAD_FOLDER = os.path.join(app.static_folder, 'images')
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = 6 * 1024 * 1024  # 6 MB

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    def admin_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not (current_user.is_authenticated and getattr(current_user, "is_admin", False)):
                flash('Admin access required', 'danger')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapper

    # ---------------- ROUTES ----------------

    @app.route('/')
    def index():
        categories = [
            {'slug': 'jhumkas', 'name': 'Jhumkas'},
            {'slug': 'bracelets', 'name': 'Bracelets'},
            {'slug': 'studs', 'name': 'Studs'},
            {'slug': 'pendants', 'name': 'Pendants'},
            {'slug': 'vintage', 'name': 'Vintage'},
            {'slug': 'rings', 'name': 'Rings'},
        ]
        return render_template('index.html', categories=categories)

    @app.route('/category/<string:category>')
    def category_page(category):
        # decode category slug; query products that match category slug
        products = Product.query.filter_by(category=category).order_by(Product.created_at.desc()).all()
        return render_template('category_page.html', products=products, category=category)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email','').strip().lower()
            password = request.form.get('password','')
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                login_user(user)
                flash('Logged in', 'success')
                # if admin redirect to admin products
                if user.is_admin:
                    return redirect(url_for('admin_products'))
                return redirect(url_for('index'))
            flash('Invalid credentials', 'danger')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Logged out', 'info')
        return redirect(url_for('index'))

    # Admin: manage products (add/delete)
    @app.route('/admin/products', methods=['GET', 'POST'])
    @login_required
    @admin_required
    def admin_products():
        categories = ['jhumkas', 'bracelets', 'studs', 'pendants', 'vintage', 'rings']
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            price = request.form.get('price', type=float)
            category = request.form.get('category')
            description = request.form.get('description', '').strip()
            # either uploaded file or typed filename
            file = request.files.get('image')
            typed_filename = request.form.get('image_url', '').strip()

            if not name or not category or not price:
                flash('Name, category and price are required.', 'danger')
                return redirect(url_for('admin_products'))

            filename = None
            # prefer uploaded file
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(save_path)
                # process image: center crop to square and resize
                try:
                    img = Image.open(save_path).convert('RGB')
                    w, h = img.size
                    min_side = min(w, h)
                    left = (w - min_side) // 2
                    top = (h - min_side) // 2
                    img = img.crop((left, top, left + min_side, top + min_side))
                    img = img.resize((IMG_WIDTH, IMG_HEIGHT), Image.LANCZOS)
                    img.save(save_path, optimize=True, quality=85)
                except Exception as e:
                    flash('Image processing failed: ' + str(e), 'warning')
            elif typed_filename:
                # ensure file exists in static/images
                if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], typed_filename)):
                    filename = typed_filename
                else:
                    flash('Typed image file not found in static/images/', 'warning')

            p = Product(name=name, description=description, price=price, category=category, image_url=filename)
            db.session.add(p)
            db.session.commit()
            flash('Product added.', 'success')
            return redirect(url_for('admin_products'))

        products = Product.query.order_by(Product.created_at.desc()).all()
        return render_template('admin_products.html', products=products, categories=categories)
    
    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route('/cart')
    def view_cart():
        return render_template('cart.html')

    @app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
    @login_required
    @admin_required
    def delete_product(product_id):
        product = Product.query.get_or_404(product_id)
        # remove image file (optional)
        if product.image_url:
            try:
                os.remove(os.path.join(app.static_folder, 'images', product.image_url))
            except OSError:
                pass
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted', 'success')
        return redirect(url_for('admin_products'))

    # create DB tables if not exists
    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
