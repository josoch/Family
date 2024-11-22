"""Add date fields to funding requests table"""
from datetime import datetime
import sqlite3

def upgrade():
    conn = sqlite3.connect('family_finance.db')
    cursor = conn.cursor()
    
    # Add new columns
    try:
        cursor.execute('ALTER TABLE funding_request ADD COLUMN updated_at DATETIME')
        print("Added updated_at column")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("updated_at column already exists")
        else:
            # Check if table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='funding_request'")
            if not cursor.fetchone():
                # Create the table if it doesn't exist
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS funding_request (
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
                ''')
                print("Created funding_request table")
            else:
                print(f"Error: {e}")

    # Update existing rows
    cursor.execute('UPDATE funding_request SET updated_at = date_requested WHERE updated_at IS NULL')
    
    conn.commit()
    conn.close()
    print("Migration completed successfully!")

if __name__ == '__main__':
    upgrade()
