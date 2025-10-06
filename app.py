# app.py
import os
from dotenv import load_dotenv

# Load environment variables before anything else
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from functools import wraps
from PIL import Image
from authlib.integrations.flask_client import OAuth
from models import db, User, Product
from config import Config
from google.oauth2 import id_token
from google.auth.transport import requests
from flask import abort
import qrcode
from io import BytesIO
import base64
from flask import request
from models import Payment
from flask import request, jsonify, make_response, session, redirect, url_for
import json

# Image settings
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'webp'}
IMG_WIDTH = 800
IMG_HEIGHT = 800

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # --- Database setup ---
    db.init_app(app)

    # --- Login manager setup ---
    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # --- OAuth setup ---
    oauth = OAuth(app)
    google = oauth.register(
        name='google',
        client_id=Config.GOOGLE_CLIENT_ID,
        client_secret=Config.GOOGLE_CLIENT_SECRET,
        access_token_url='https://accounts.google.com/o/oauth2/token',
        access_token_params=None,
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params={'prompt': 'select_account'},
        api_base_url='https://www.googleapis.com/oauth2/v1/',
        client_kwargs={'scope': 'openid email profile'}
    )
    @app.route('/category/<category>')
    def category_page(category):
        # Fetch products by category
        products = Product.query.filter_by(category=category).all()
        return render_template('category_page.html', category=category, products=products)

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

    # ---------------- AUTH ROUTES ----------------
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                login_user(user)
                flash('Logged in successfully.', 'success')

                # Redirect based on role
                if user.is_admin:
                    return redirect(url_for('admin_products'))
                else:
                    return redirect(url_for('index'))

            flash('Invalid credentials', 'danger')
        return render_template('login.html')

    @app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
    @login_required
    def delete_product(product_id):
        if not current_user.is_admin:
            flash('Admin access required', 'danger')
            return redirect(url_for('index'))

        product = Product.query.get_or_404(product_id)
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully.', 'success')
        return redirect(url_for('admin_products'))
    
#signup

    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            # Get form data
            name = request.form.get('name', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm = request.form.get('confirm', '')

            # Password match check
            if password != confirm:
                flash("Passwords do not match", "danger")
                return redirect(url_for('signup'))

            # Email uniqueness check
            if User.query.filter_by(email=email).first():
                flash("Email already registered", "warning")
                return redirect(url_for('signup'))

            # Create user and save to DB
            user = User(name=name, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            flash("Account created! Please login.", "success")
            return redirect(url_for('login'))

        return render_template('signup.html')

    # ---------------- GOOGLE LOGIN USING TOKEN ----------------
    @app.route("/google_login", methods=["POST"])
    def google_login_token():
        """
        Handles login/signup using Google OAuth token sent from frontend.
        """
        try:
            data = request.get_json()
            token = data.get("credential")
            if not token:
                return jsonify({"error": "Missing token"}), 400

            idinfo = id_token.verify_oauth2_token(token, requests.Request(), Config.GOOGLE_CLIENT_ID)
            email = idinfo.get("email")
            name = idinfo.get("name")

            if not email:
                return jsonify({"error": "Email not found"}), 400

            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(email=email)
                user.set_password("google_oauth_user")  # dummy password
                db.session.add(user)
                db.session.commit()

            login_user(user)
            return jsonify({"message": "Login successful"}), 200

        except ValueError:
            return jsonify({"error": "Invalid token"}), 400
        except Exception as e:
            print("Google login error:", e)
            return jsonify({"error": "Something went wrong"}), 500

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Logged out', 'info')
        return redirect(url_for('index'))


    

#checkout
    @app.route('/checkout', methods=['GET', 'POST'])
    def checkout():
        cart = []  # We'll calculate the amount from JS/cart later or pass it from session
        # For demo, let's assume the amount comes from query param or session
        amount = request.args.get('amount', 0)

        # Generate QR code for your UPI
        upi_id = "7798865037@kotak811"
        qr_img = qrcode.make(f"upi://pay?pa={upi_id}&pn=Bloomera&tn=Order+Payment&am={amount}")

        buffered = BytesIO()
        qr_img.save(buffered, format="PNG")
        qr_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

        if request.method == 'POST':
            email = request.form.get('email')
            transaction_id = request.form.get('transaction_id')

            if not email or not transaction_id:
                flash("Please provide both email and transaction ID.", "danger")
                return redirect(request.url)

            payment = Payment(email=email, transaction_id=transaction_id, amount=float(amount))
            db.session.add(payment)
            db.session.commit()

            # Optional: Send email here using Flask-Mail (you already added it)
            flash("Payment info submitted. Thank you!", "success")
            return redirect(url_for('index'))

        return render_template("checkout.html", qr_b64=qr_b64, amount=amount)


        # Generate QR code for your UPI ID
        upi_id = "7798865037@kotak811"
        qr = qrcode.make(f"upi://pay?pa={upi_id}&pn=Bloomera&tn=Order+Payment&am={amount}")
        buffered = BytesIO()
        qr.save(buffered, format="JPEG")
        qr_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

        return render_template("checkout.html", amount=amount, qr_b64=qr_b64)


    @app.route('/add_product', methods=['GET', 'POST'])
    @login_required
    def add_product():
        if not current_user.is_admin: 
            abort(403)  # Forbidden
        if request.method == 'POST':
            # handle product addition
            pass
        return render_template('add_product.html')
    # ---------------- GOOGLE OAUTH ROUTES ----------------
    @app.route('/auth/google')
    def google_authorize_redirect():
        redirect_uri = url_for('google_callback', _external=True)
        return google.authorize_redirect(redirect_uri)

    @app.route('/auth/callback')
    def google_callback():
        token = google.authorize_access_token()
        resp = google.get('userinfo')
        user_info = resp.json()

        email = user_info['email']
        user = User.query.filter_by(email=email).first()

        if not user:
            user = User(email=email)
            db.session.add(user)
            db.session.commit()

        login_user(user)
        flash('Logged in via Google.', 'success')
        return redirect(url_for('index'))

    # ---------------- ADMIN ROUTES ----------------
    @app.route('/admin/products', methods=['GET', 'POST'])
    @login_required
    def admin_products():
        if not current_user.is_admin:
            flash('Admin access required', 'danger')
            return redirect(url_for('index'))

        categories = ['jhumkas', 'bracelets', 'studs', 'pendants', 'vintage', 'rings']

        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            price = request.form.get('price', type=float)
            category = request.form.get('category')
            description = request.form.get('description', '').strip()
            file = request.files.get('image')

            if not name or not category or not price:
                flash('Name, category and price are required.', 'danger')
                return redirect(url_for('admin_products'))

            filename = None
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                save_path = os.path.join(app.static_folder, 'images', filename)
                file.save(save_path)

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
                    flash(f"Image processing failed: {e}", 'warning')

            product = Product(name=name, description=description, price=price, category=category, image_url=filename)
            db.session.add(product)
            db.session.commit()
            flash('Product added.', 'success')
            return redirect(url_for('admin_products'))

        products = Product.query.order_by(Product.created_at.desc()).all()
        return render_template('admin_products.html', products=products, categories=categories)

    # ---------------- OTHER ROUTES ----------------
    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route('/cart')
    def view_cart():
        return render_template('cart.html')

    # ---------------- INITIALIZE DB ----------------
    with app.app_context():
        db.create_all()

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
