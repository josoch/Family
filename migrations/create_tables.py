"""Create database tables with explicit schema"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import db, app

def create_tables():
    with app.app_context():
        # Remove existing database
        try:
            os.remove('family_finance.db')
            print("Removed existing database")
        except FileNotFoundError:
            print("No existing database found")

        # Create tables with explicit schema
        db.session.execute(db.text('''
            CREATE TABLE family (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(100) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        '''))

        db.session.execute(db.text('''
            CREATE TABLE user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(80) NOT NULL UNIQUE,
                email VARCHAR(120) NOT NULL UNIQUE,
                password_hash VARCHAR(128) NOT NULL,
                role VARCHAR(20) NOT NULL,
                family_id INTEGER NOT NULL,
                balance FLOAT DEFAULT 0.0,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (family_id) REFERENCES family (id)
            )
        '''))

        db.session.execute(db.text('''
            CREATE TABLE financial_transaction (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                amount FLOAT NOT NULL,
                category VARCHAR(50) NOT NULL,
                description TEXT,
                transaction_type VARCHAR(20) NOT NULL,
                date DATETIME DEFAULT CURRENT_TIMESTAMP,
                family_id INTEGER NOT NULL,
                created_by INTEGER NOT NULL,
                payee_id INTEGER,
                FOREIGN KEY (family_id) REFERENCES family (id),
                FOREIGN KEY (created_by) REFERENCES user (id),
                FOREIGN KEY (payee_id) REFERENCES user (id)
            )
        '''))

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
                date_requested DATETIME DEFAULT CURRENT_TIMESTAMP,
                approved_date DATETIME,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (requested_by) REFERENCES user (id),
                FOREIGN KEY (approved_by) REFERENCES user (id),
                FOREIGN KEY (family_id) REFERENCES family (id)
            )
        '''))

        # Create indexes
        db.session.execute(db.text('CREATE INDEX idx_user_family ON user(family_id)'))
        db.session.execute(db.text('CREATE INDEX idx_user_username ON user(username)'))
        db.session.execute(db.text('CREATE INDEX idx_user_email ON user(email)'))
        
        db.session.execute(db.text('CREATE INDEX idx_transaction_family ON financial_transaction(family_id)'))
        db.session.execute(db.text('CREATE INDEX idx_transaction_date ON financial_transaction(date)'))
        db.session.execute(db.text('CREATE INDEX idx_transaction_creator ON financial_transaction(created_by)'))
        
        db.session.execute(db.text('CREATE INDEX idx_funding_request_family ON funding_request(family_id)'))
        db.session.execute(db.text('CREATE INDEX idx_funding_request_status ON funding_request(status)'))
        db.session.execute(db.text('CREATE INDEX idx_funding_request_date ON funding_request(date_requested)'))

        db.session.commit()
        print("Created all tables and indexes with explicit schema")

if __name__ == '__main__':
    create_tables()
