from models import db, User, Product
from app import create_app

app = create_app()

with app.app_context():
    # Create admin user if not exists
    if not User.query.filter_by(email='admin@bloomera.com').first():
        admin = User(name='Admin', email='admin@bloomera.com', is_admin=True)
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

    # Add demo products if none exist
    if Product.query.count() == 0:
        demo = [
            {"name": "Solitaire Diamond Ring", "price": 4999, "description": "Elegant solitaire diamond ring", "image_url": "solitaire.jpg"},
            {"name": "Gold Necklace", "price": 6999, "description": "24K gold necklace", "image_url": "gold_necklace.jpg"},
            {"name": "Pearl Earrings", "price": 2999, "description": "Classic pearl earrings", "image_url": "pearl_earrings.jpg"}
        ]

        for item in demo:
            product = Product(
                name=item["name"],
                price=item["price"],
                description=item["description"],
                image_url=item["image_url"]
            )
            db.session.add(product)
        db.session.commit()

print("Database seeded successfully!")
