from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import re
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///c:/Users/user/CascadeProjects/Family/instance/family.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes session timeout

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class Family(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    family_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    users = db.relationship('User', backref='family', lazy=True)
    transactions = db.relationship('Transaction', backref='family', lazy=True)
    funding_requests = db.relationship('FundingRequest', backref=db.backref('family', lazy=True))

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    transaction_type = db.Column(db.String(20), nullable=False)  # 'income' or 'expense'
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'father', 'mother', 'child'
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    balance = db.Column(db.Float, default=0.0)
    transactions_created = db.relationship('Transaction', backref='creator', foreign_keys=[Transaction.created_by], lazy=True)
    transactions_received = db.relationship('Transaction', backref='payee', foreign_keys=[Transaction.payee_id], lazy=True)
    requests_created = db.relationship('FundingRequest', foreign_keys='FundingRequest.requested_by', backref='requester', lazy=True)
    requests_approved = db.relationship('FundingRequest', foreign_keys='FundingRequest.approved_by', backref='approver', lazy=True)

    def set_password(self, password):
        if not self.is_password_valid(password):
            raise ValueError("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @staticmethod
    def is_password_valid(password):
        # Password must be at least 8 characters long and contain at least one uppercase letter,
        # one lowercase letter, and one number
        if len(password) < 8:
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"\d", password):
            return False
        return True
    
    @staticmethod
    def is_email_valid(email):
        # Basic email validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

class FundingRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date_requested = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'), nullable=False)
    requested_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_date = db.Column(db.DateTime, nullable=True)
    comments = db.Column(db.Text, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Custom decorators
def father_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'father':
            flash('This action requires father privileges')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def family_member_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_active:
            flash('Your account is not active')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Helper functions
def create_family(family_name, father_username, father_email, father_password):
    # Check if a family with this name already exists
    if Family.query.filter_by(family_name=family_name).first():
        raise ValueError("A family with this name already exists")
    
    # Create new family
    family = Family(family_name=family_name)
    db.session.add(family)
    db.session.flush()  # This gets us the family.id
    
    # Create father user
    father = User(
        username=father_username,
        email=father_email,
        role='father',
        family_id=family.id
    )
    father.set_password(father_password)
    db.session.add(father)
    
    try:
        db.session.commit()
        return family
    except Exception as e:
        db.session.rollback()
        raise e

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account has been deactivated. Please contact your family administrator.')
                return redirect(url_for('login'))
                
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        family_name = request.form.get('family_name')
        
        # Validate input
        if not all([username, email, password, role]):
            flash('All fields are required')
            return redirect(url_for('register'))
        
        if not User.is_email_valid(email):
            flash('Invalid email address')
            return redirect(url_for('register'))
        
        if not User.is_password_valid(password):
            flash('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number')
            return redirect(url_for('register'))
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('register'))
        
        try:
            if role == 'father':
                # Create new family with father
                create_family(family_name, username, email, password)
                flash('Family created successfully! Please login.')
            else:
                # For mother/child, they need to be added by the father
                flash('Only fathers can create new family accounts. Please ask your family administrator to add you.')
                return redirect(url_for('register'))
                
            return redirect(url_for('login'))
            
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('register'))
        except Exception as e:
            flash('An error occurred. Please try again.')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/add_transaction', methods=['GET', 'POST'])
@login_required
def add_transaction():
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount'))
            category = request.form.get('category')
            description = request.form.get('description')
            transaction_type = request.form.get('transaction_type')
            payee_id = request.form.get('payee_id')
            
            if payee_id:
                payee_id = int(payee_id)
                payee = User.query.get(payee_id)
                if not payee or payee.family_id != current_user.family_id:
                    flash('Invalid payee selected.', 'error')
                    return redirect(url_for('add_transaction'))
                
                # Update payee's balance
                if transaction_type == 'expense':
                    payee.balance += amount
                else:
                    payee.balance -= amount

            # Create transaction
            transaction = Transaction(
                amount=amount,
                category=category,
                description=description,
                transaction_type=transaction_type,
                family_id=current_user.family_id,
                created_by=current_user.id,
                payee_id=payee_id if payee_id else None
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            flash('Transaction added successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except ValueError:
            flash('Please enter valid values.', 'error')
            return redirect(url_for('add_transaction'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('add_transaction'))
    
    family_members = User.query.filter_by(family_id=current_user.family_id).all()
    return render_template('add_transaction.html', family_members=family_members)

@app.route('/edit_transaction/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_transaction(id):
    transaction = Transaction.query.get_or_404(id)
    
    # Ensure users can only edit transactions from their family
    if transaction.family_id != current_user.family_id:
        flash('You do not have permission to edit this transaction')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        transaction.amount = float(request.form.get('amount'))
        transaction.category = request.form.get('category')
        transaction.description = request.form.get('description')
        transaction.transaction_type = request.form.get('transaction_type')
        
        db.session.commit()
        flash('Transaction updated successfully')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_transaction.html', transaction=transaction)

@app.route('/delete_transaction/<int:id>')
@login_required
def delete_transaction(id):
    transaction = Transaction.query.get_or_404(id)
    
    # Ensure users can only delete transactions from their family
    if transaction.family_id != current_user.family_id:
        flash('You do not have permission to delete this transaction')
        return redirect(url_for('dashboard'))
    
    db.session.delete(transaction)
    db.session.commit()
    flash('Transaction deleted successfully')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_family_member', methods=['GET', 'POST'])
@login_required
@father_required
def add_family_member():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if role == 'father':
            flash('Cannot add another father to the family')
            return redirect(url_for('add_family_member'))
        
        if not all([username, email, password, role]):
            flash('All fields are required')
            return redirect(url_for('add_family_member'))
            
        if not User.is_email_valid(email):
            flash('Invalid email address')
            return redirect(url_for('add_family_member'))
            
        if not User.is_password_valid(password):
            flash('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number')
            return redirect(url_for('add_family_member'))
            
        try:
            # Check if username or email already exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists')
                return redirect(url_for('add_family_member'))
                
            if User.query.filter_by(email=email).first():
                flash('Email already exists')
                return redirect(url_for('add_family_member'))
            
            new_user = User(
                username=username,
                email=email,
                role=role,
                family_id=current_user.family_id
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash(f'Successfully added new family member: {username}')
            return redirect(url_for('dashboard'))
        except IntegrityError:
            db.session.rollback()
            flash('Database error: Username or email already exists')
            return redirect(url_for('add_family_member'))
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('add_family_member'))
        except Exception as e:
            db.session.rollback()
            flash(f'An unexpected error occurred: {str(e)}')
            return redirect(url_for('add_family_member'))
            
    return render_template('add_family_member.html')

@app.route('/manage_family_members')
@login_required
@father_required
def manage_family_members():
    family_members = User.query.filter_by(family_id=current_user.family_id).all()
    return render_template('manage_family_members.html', family_members=family_members)

@app.route('/toggle_member_status/<int:user_id>')
@login_required
@father_required
def toggle_member_status(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.family_id != current_user.family_id:
        flash('You can only manage members of your own family')
        return redirect(url_for('manage_family_members'))
        
    if user.role == 'father':
        flash('Cannot deactivate father account')
        return redirect(url_for('manage_family_members'))
        
    user.is_active = not user.is_active
    db.session.commit()
    flash(f"User {user.username} {'activated' if user.is_active else 'deactivated'} successfully")
    return redirect(url_for('manage_family_members'))

@app.route('/funding_requests')
@login_required
def funding_requests():
    """View all funding requests for the family."""
    requests = FundingRequest.query.filter_by(family_id=current_user.family_id)\
        .order_by(FundingRequest.date_requested.desc()).all()
    return render_template('funding_requests.html', requests=requests)

@app.route('/funding_requests/add', methods=['GET', 'POST'])
@login_required
def add_funding_request():
    """Add a new funding request."""
    if request.method == 'POST':
        try:
            # Get form data
            title = request.form.get('title')
            description = request.form.get('description')
            amount = float(request.form.get('amount'))

            # Validate input
            if not title or not description or amount <= 0:
                flash('Please fill in all fields with valid values.', 'error')
                return redirect(url_for('add_funding_request'))

            # Create new funding request
            new_request = FundingRequest(
                title=title,
                description=description,
                amount=amount,
                family_id=current_user.family_id,
                requested_by=current_user.id,
                status='pending'
            )
            db.session.add(new_request)
            db.session.commit()

            flash('Funding request submitted successfully!', 'success')
            return redirect(url_for('funding_requests'))

        except ValueError:
            flash('Please enter a valid amount.', 'error')
            return redirect(url_for('add_funding_request'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while submitting your request. Please try again.', 'error')
            return redirect(url_for('add_funding_request'))

    return render_template('add_funding_request.html')

@app.route('/funding_requests/<int:id>/approve', methods=['POST'])
@login_required
@father_required
def approve_funding_request(id):
    """Approve or reject a funding request (father only)."""
    try:
        funding_request = FundingRequest.query.filter_by(
            id=id,
            family_id=current_user.family_id
        ).first_or_404()

        # Only pending requests can be approved/rejected
        if funding_request.status != 'pending':
            flash('This request has already been processed.', 'error')
            return redirect(url_for('funding_requests'))

        # Get form data
        status = request.form.get('status')
        comments = request.form.get('comments')

        if status not in ['approved', 'rejected']:
            flash('Invalid status provided.', 'error')
            return redirect(url_for('funding_requests'))

        # Update request
        funding_request.status = status
        funding_request.approved_by = current_user.id
        funding_request.approved_date = datetime.utcnow()
        funding_request.comments = comments

        # If approved, create a transaction and update requester's balance
        if status == 'approved':
            # Update requester's balance
            requester = User.query.get(funding_request.requested_by)
            requester.balance += funding_request.amount
            
            # Create transaction
            transaction = Transaction(
                amount=funding_request.amount,
                category='Funding Request',
                description=f'Approved funding request: {funding_request.title}',
                transaction_type='expense',
                family_id=current_user.family_id,
                created_by=current_user.id,
                payee_id=funding_request.requested_by
            )
            db.session.add(transaction)

        db.session.commit()
        flash(f'Funding request {status} successfully!', 'success')

    except Exception as e:
        db.session.rollback()
        flash('An error occurred while processing the request. Please try again.', 'error')

    return redirect(url_for('funding_requests'))

@app.route('/dashboard')
@login_required
def dashboard():
    transactions = Transaction.query.filter_by(family_id=current_user.family_id).order_by(Transaction.date.desc()).all()
    
    total_income = sum(t.amount for t in transactions if t.transaction_type == 'income')
    total_expense = sum(t.amount for t in transactions if t.transaction_type == 'expense')
    balance = total_income - total_expense
    
    # Get user's personal balance
    user_balance = current_user.balance
    
    return render_template('dashboard.html', 
                         transactions=transactions,
                         total_income=total_income,
                         total_expense=total_expense,
                         balance=balance,
                         user_balance=user_balance)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
