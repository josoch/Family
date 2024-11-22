"""Recreate funding_request table with correct schema"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import db, app

def recreate_funding_request():
    with app.app_context():
        try:
            # Drop existing table
            db.session.execute(db.text('DROP TABLE IF EXISTS funding_request'))
            
            # Create table with correct schema
            db.session.execute(db.text('''
                CREATE TABLE funding_request (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title VARCHAR(100) NOT NULL,
                    description TEXT,
                    amount FLOAT NOT NULL,
                    status VARCHAR(20) DEFAULT 'pending',
                    requested_by INTEGER NOT NULL,
                    approved_by INTEGER,
                    family_id INTEGER NOT NULL,
                    comments TEXT,
                    date_requested DATETIME DEFAULT (datetime('now')),
                    approved_date DATETIME,
                    updated_at DATETIME DEFAULT (datetime('now')),
                    FOREIGN KEY (requested_by) REFERENCES user (id),
                    FOREIGN KEY (approved_by) REFERENCES user (id),
                    FOREIGN KEY (family_id) REFERENCES family (id)
                )
            '''))
            
            # Create indexes
            db.session.execute(db.text('CREATE INDEX idx_funding_request_family ON funding_request(family_id)'))
            db.session.execute(db.text('CREATE INDEX idx_funding_request_status ON funding_request(status)'))
            db.session.execute(db.text('CREATE INDEX idx_funding_request_date ON funding_request(date_requested)'))
            
            # Create trigger for updated_at
            db.session.execute(db.text('''
                CREATE TRIGGER IF NOT EXISTS funding_request_updated_at 
                AFTER UPDATE ON funding_request
                BEGIN
                    UPDATE funding_request 
                    SET updated_at = datetime('now')
                    WHERE id = NEW.id;
                END;
            '''))
            
            db.session.commit()
            print("Recreated funding_request table with correct schema")
            
        except Exception as e:
            print(f"Error: {str(e)}")
            db.session.rollback()

if __name__ == '__main__':
    recreate_funding_request()
