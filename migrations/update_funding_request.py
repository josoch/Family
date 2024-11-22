"""Update funding request table schema"""
import sqlite3

def update_schema():
    conn = sqlite3.connect('family_finance.db')
    cursor = conn.cursor()
    
    # Check if funding_request table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='funding_request'")
    if not cursor.fetchone():
        # Create the table with all columns
        cursor.execute('''
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
        ''')
        print("Created funding_request table")
    else:
        # Add any missing columns
        try:
            cursor.execute('ALTER TABLE funding_request ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP')
            print("Added updated_at column")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("updated_at column already exists")
            else:
                print(f"Error adding updated_at column: {e}")

        try:
            cursor.execute('ALTER TABLE funding_request ADD COLUMN date_requested DATETIME DEFAULT CURRENT_TIMESTAMP')
            print("Added date_requested column")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("date_requested column already exists")
            else:
                print(f"Error adding date_requested column: {e}")

        try:
            cursor.execute('ALTER TABLE funding_request ADD COLUMN approved_date DATETIME')
            print("Added approved_date column")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("approved_date column already exists")
            else:
                print(f"Error adding approved_date column: {e}")

    conn.commit()
    conn.close()
    print("Schema update completed")

if __name__ == '__main__':
    update_schema()
