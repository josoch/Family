"""Create database tables with explicit schema"""
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import db, app

def create_tables():
    with app.app_context():
        # Drop existing tables
        tables = [
            'funding_request_transaction',
            'funding_request_balance',
            'financial_transaction',
            'funding_request',
            'user',
            'family'
        ]
        
        for table in tables:
            try:
                db.session.execute(db.text(f'DROP TABLE IF EXISTS {table}'))
                print(f"Dropped table {table}")
            except Exception as e:
                print(f"Error dropping {table}: {str(e)}")
        
        db.session.commit()
        print("Dropped all existing tables")

        # Remove existing database
        try:
            os.remove('family.db')  # Updated database name to match app.py
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
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (family_id) REFERENCES family (id)
            )
        '''))

        db.session.execute(db.text('''
            CREATE TABLE financial_transaction (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                amount FLOAT NOT NULL,
                category VARCHAR(50) NOT NULL,
                description VARCHAR(200),
                transaction_type VARCHAR(20) NOT NULL,
                created_by INTEGER NOT NULL,
                payee_id INTEGER,
                family_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
                family_id INTEGER NOT NULL,
                requested_by INTEGER NOT NULL,
                approved_by INTEGER,
                approved_date DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (requested_by) REFERENCES user (id),
                FOREIGN KEY (approved_by) REFERENCES user (id),
                FOREIGN KEY (family_id) REFERENCES family (id)
            )
        '''))

        db.session.execute(db.text('''
            CREATE TABLE funding_request_balance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                funding_request_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                allocated_amount FLOAT NOT NULL,
                remaining_balance FLOAT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (funding_request_id) REFERENCES funding_request (id),
                FOREIGN KEY (user_id) REFERENCES user (id)
            )
        '''))

        db.session.execute(db.text('''
            CREATE TABLE funding_request_transaction (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                funding_request_id INTEGER NOT NULL,
                transaction_id INTEGER NOT NULL,
                amount FLOAT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (funding_request_id) REFERENCES funding_request (id),
                FOREIGN KEY (transaction_id) REFERENCES financial_transaction (id)
            )
        '''))

        # Create indexes
        db.session.execute(db.text('CREATE INDEX idx_user_family ON user(family_id)'))
        db.session.execute(db.text('CREATE INDEX idx_user_username ON user(username)'))
        db.session.execute(db.text('CREATE INDEX idx_user_email ON user(email)'))
        
        db.session.execute(db.text('CREATE INDEX idx_transaction_family ON financial_transaction(family_id)'))
        db.session.execute(db.text('CREATE INDEX idx_transaction_created_at ON financial_transaction(created_at)'))
        db.session.execute(db.text('CREATE INDEX idx_transaction_creator ON financial_transaction(created_by)'))
        
        db.session.execute(db.text('CREATE INDEX idx_funding_request_family ON funding_request(family_id)'))
        db.session.execute(db.text('CREATE INDEX idx_funding_request_status ON funding_request(status)'))
        db.session.execute(db.text('CREATE INDEX idx_funding_request_created ON funding_request(created_at)'))
        
        db.session.execute(db.text('CREATE INDEX idx_funding_balance_request ON funding_request_balance(funding_request_id)'))
        db.session.execute(db.text('CREATE INDEX idx_funding_balance_user ON funding_request_balance(user_id)'))
        
        db.session.execute(db.text('CREATE INDEX idx_funding_transaction_request ON funding_request_transaction(funding_request_id)'))
        db.session.execute(db.text('CREATE INDEX idx_funding_transaction_trans ON funding_request_transaction(transaction_id)'))

        db.session.commit()
        print("Created all tables and indexes with explicit schema")

if __name__ == '__main__':
    create_tables()
