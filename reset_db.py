from attsys import app, db, init_db

with app.app_context():
    print("Dropping all tables...")
    db.drop_all()
    print("Creating all tables...")
    db.create_all()
    print("Initializing database...")
    init_db()
    print("Database reset and initialized successfully.")