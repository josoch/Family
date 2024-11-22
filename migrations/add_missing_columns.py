"""Add missing columns to funding_request table"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import db, app

def add_missing_columns():
    with app.app_context():
        try:
            # Add missing columns one by one
            commands = [
                "ALTER TABLE funding_request ADD COLUMN date_requested DATETIME DEFAULT CURRENT_TIMESTAMP",
                "ALTER TABLE funding_request ADD COLUMN approved_date DATETIME",
                "ALTER TABLE funding_request ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP"
            ]
            
            for cmd in commands:
                try:
                    db.session.execute(db.text(cmd))
                    print(f"Executed: {cmd}")
                except Exception as e:
                    print(f"Note: {str(e)}")  # Column might already exist
            
            db.session.commit()
            print("Added missing columns to funding_request table")
            
        except Exception as e:
            print(f"Error: {str(e)}")
            db.session.rollback()

if __name__ == '__main__':
    add_missing_columns()
