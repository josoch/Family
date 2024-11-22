"""Recreate the database with updated schema"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import db, app
from sqlalchemy import text

def recreate_database():
    with app.app_context():
        # Remove existing database
        try:
            os.remove('family_finance.db')
            print("Removed existing database")
        except FileNotFoundError:
            print("No existing database found")

        # Create new database with all tables
        db.create_all()
        print("Created new database with updated schema")

        # Create indexes for better performance
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_funding_request_family ON funding_request(family_id)'))
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_funding_request_status ON funding_request(status)'))
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_funding_request_date ON funding_request(date_requested)'))
        db.session.commit()
        print("Created database indexes")

if __name__ == '__main__':
    recreate_database()
