import sqlite3
from datetime import datetime

# Connect to the database
conn = sqlite3.connect('instance/family_finance.db')
cursor = conn.cursor()

# Create a default family if it doesn't exist
cursor.execute('''
CREATE TABLE IF NOT EXISTS family (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    family_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP
)
''')

cursor.execute('''
INSERT INTO family (family_name, created_at)
SELECT 'Default Family', CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM family WHERE family_name = 'Default Family')
''')

# Get the default family ID
cursor.execute('SELECT id FROM family WHERE family_name = ?', ('Default Family',))
default_family_id = cursor.fetchone()[0]

# Create a new table with all the constraints we want
cursor.execute('''
CREATE TABLE IF NOT EXISTS user_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(120) NOT NULL,
    role VARCHAR(20) NOT NULL,
    family_id INTEGER NOT NULL REFERENCES family(id),
    is_active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP,
    last_login TIMESTAMP
)
''')

# Copy data from old table to new table with current timestamp for created_at
current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

try:
    # Copy data to new table, generating email from username
    cursor.execute(f'''
    INSERT INTO user_new (
        id, username, email, password_hash, role, family_id, 
        is_active, created_at, last_login
    )
    SELECT 
        id, 
        username, 
        username || '@example.com',  -- Generate email from username
        password_hash, 
        role, 
        ?,  -- Use default family ID
        1,  -- Set is_active to true
        ?,  -- Use current timestamp
        NULL  -- Set last_login to NULL
    FROM user
    ''', (default_family_id, current_time))
    
    # Drop old table and rename new table
    cursor.execute('DROP TABLE user')
    cursor.execute('ALTER TABLE user_new RENAME TO user')
    print("Successfully restructured user table with proper constraints")
except sqlite3.IntegrityError as e:
    print(f"Error during table restructure: {e}")
    print("Rolling back to original table structure")
    cursor.execute('DROP TABLE IF EXISTS user_new')

# Commit the changes and close the connection
conn.commit()
conn.close()

print("Database update completed successfully!")
