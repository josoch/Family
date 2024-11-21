# Family Finance Tracker

A web-based application for families to track their income and expenses with different user roles (Father, Mother, and Children).

## Features

- User authentication with role-based access (Father, Mother, Child)
- Track income and expenses
- Categorized transactions
- Dashboard with financial overview
- Transaction history
- Responsive design for all devices

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation

1. Clone the repository or download the source code

2. Create a virtual environment (recommended):
```bash
python -m venv venv
venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

## Running the Application

1. Activate the virtual environment (if not already activated):
```bash
venv\Scripts\activate
```

2. Run the Flask application:
```bash
python app.py
```

3. Open your web browser and navigate to:
```
http://localhost:5000
```

## Usage

1. Register a new account with one of the following roles:
   - Father
   - Mother
   - Child

2. Log in with your credentials

3. Use the dashboard to:
   - View financial overview
   - Add new transactions
   - View transaction history

## Security Notes

- Change the secret key in `app.py` before deploying to production
- Use strong passwords for all accounts
- Keep your dependencies updated

## License

This project is licensed under the MIT License.
