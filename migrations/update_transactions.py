import os
import sys

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, Transaction, User
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, Float, String, DateTime, ForeignKey
from datetime import datetime

def update_transactions():
    try:
        # Get the database URI from the app config
        database_uri = app.config['SQLALCHEMY_DATABASE_URI']
        engine = create_engine(database_uri)
        metadata = MetaData()

        # Define the old transactions table structure
        old_transactions = Table(
            'transaction',
            metadata,
            Column('id', Integer, primary_key=True),
            Column('amount', Float, nullable=False),
            Column('category', String(50), nullable=False),
            Column('description', String(200)),
            Column('date', DateTime, nullable=False),
            Column('transaction_type', String(20), nullable=False),
            Column('user_id', Integer, ForeignKey('user.id'), nullable=False)
        )

        # Backup existing data
        with engine.connect() as connection:
            # Read existing data
            result = connection.execute(old_transactions.select())
            transactions_backup = [dict(row) for row in result]

            # Drop the old table
            old_transactions.drop(engine, checkfirst=True)

            # Create the new table structure through SQLAlchemy models
            with app.app_context():
                db.create_all()

                # Restore the data with the new schema
                for t in transactions_backup:
                    user = User.query.get(t['user_id'])
                    if user:
                        new_transaction = Transaction(
                            amount=t['amount'],
                            category=t['category'],
                            description=t['description'],
                            date=t['date'],
                            transaction_type=t['transaction_type'],
                            family_id=user.family_id,
                            created_by=user.id
                        )
                        db.session.add(new_transaction)
                
                db.session.commit()
                print("Successfully migrated transactions to new schema")

    except Exception as e:
        print(f"Error during migration: {str(e)}")
        if 'db' in locals() and hasattr(db, 'session'):
            db.session.rollback()

if __name__ == '__main__':
    update_transactions()
