import sqlite3

# Connect to the database
conn = sqlite3.connect('instance/family_finance.db')
cursor = conn.cursor()

# Create the family table
cursor.execute('''
CREATE TABLE IF NOT EXISTS family (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    family_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Add new columns to user table
try:
    cursor.execute('ALTER TABLE user ADD COLUMN email VARCHAR(120) UNIQUE')
except sqlite3.OperationalError:
    print("Email column already exists")

try:
    cursor.execute('ALTER TABLE user ADD COLUMN family_id INTEGER REFERENCES family(id)')
except sqlite3.OperationalError:
    print("Family_id column already exists")

try:
    cursor.execute('ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1')
except sqlite3.OperationalError:
    print("Is_active column already exists")

try:
    cursor.execute('ALTER TABLE user ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
except sqlite3.OperationalError:
    print("Created_at column already exists")

try:
    cursor.execute('ALTER TABLE user ADD COLUMN last_login TIMESTAMP')
except sqlite3.OperationalError:
    print("Last_login column already exists")

# Commit the changes and close the connection
conn.commit()
conn.close()

print("Database migration completed successfully!")
