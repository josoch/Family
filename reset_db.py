import os
import sqlite3
from app import db, app

# Delete the existing database file
db_path = 'instance/family_finance.db'
if os.path.exists(db_path):
    os.remove(db_path)
    print("Old database deleted.")

# Create new database with updated schema
with app.app_context():
    db.create_all()
    print("New database created with updated schema.")

print("Database reset complete!")
