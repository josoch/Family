from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import re
from sqlalchemy.exc import IntegrityError
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, FloatField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, NumberRange, ValidationError

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
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    members = db.relationship('User', backref='family', lazy=True)
    transactions = db.relationship('Transaction', backref='family', lazy=True)
    funding_requests = db.relationship('FundingRequest', backref='family', lazy=True)

class Transaction(db.Model):
    __tablename__ = 'financial_transaction'
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    transaction_type = db.Column(db.String(20), nullable=False)  # income/expense
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Define relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='transactions_created')
    payee = db.relationship('User', foreign_keys=[payee_id], backref='transactions_received')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    is_active = db.Column(db.Boolean, default=True)
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships for funding requests
    funding_requests = db.relationship('FundingRequest',
                                     foreign_keys='FundingRequest.requested_by',
                                     backref=db.backref('requester_ref', lazy=True),
                                     lazy=True)
    requests_approved = db.relationship('FundingRequest',
                                      foreign_keys='FundingRequest.approved_by',
                                      backref=db.backref('approver_ref', lazy=True),
                                      lazy=True)
    funding_request_balances = db.relationship('FundingRequestBalance',
                                             backref='user_ref',
                                             lazy=True)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        # Check password complexity requirements
        if len(password) < 8:
            raise ValueError('Password must be at least 8 characters long')
        
        # Check for at least one uppercase letter
        if not any(c.isupper() for c in password):
            raise ValueError('Password must contain at least one uppercase letter')
            
        # Check for at least one lowercase letter
        if not any(c.islower() for c in password):
            raise ValueError('Password must contain at least one lowercase letter')
            
        # Check for at least one number
        if not any(c.isdigit() for c in password):
            raise ValueError('Password must contain at least one number')
            
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def validate_email(email):
        # Basic email validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

class FundingRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'), nullable=False)
    requested_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    approved_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                          onupdate=db.text('CURRENT_TIMESTAMP'))

    # Relationships
    requester = db.relationship('User', foreign_keys=[requested_by], backref='requests_created')
    approver = db.relationship('User', foreign_keys=[approved_by])  # Remove backref since it's defined in User model
    request_balances = db.relationship('FundingRequestBalance', backref='request', lazy=True)
    request_transactions = db.relationship('FundingRequestTransaction', backref='request', lazy=True)

class FundingRequestBalance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    funding_request_id = db.Column(db.Integer, db.ForeignKey('funding_request.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    allocated_amount = db.Column(db.Float, nullable=False)
    remaining_balance = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref='balance_records')

class FundingRequestTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    funding_request_id = db.Column(db.Integer, db.ForeignKey('funding_request.id'), nullable=False)
    transaction_id = db.Column(db.Integer, db.ForeignKey('financial_transaction.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    transaction = db.relationship('Transaction')

# Form Classes
class TransactionForm(FlaskForm):
    amount = FloatField('Amount', validators=[
        DataRequired(),
        NumberRange(min=0.01, message="Amount must be greater than 0")
    ])
    category = SelectField('Category', validators=[DataRequired()], choices=[
        ('Food', 'Food'),
        ('Transportation', 'Transportation'),
        ('Utilities', 'Utilities'),
        ('Entertainment', 'Entertainment'),
        ('Education', 'Education'),
        ('Healthcare', 'Healthcare'),
        ('Shopping', 'Shopping'),
        ('Other', 'Other')
    ])
    description = TextAreaField('Description')
    transaction_type = SelectField('Type', validators=[DataRequired()], choices=[
        ('income', 'Income'),
        ('expense', 'Expense')
    ])
    payee = SelectField('Payee', coerce=int)
    funding_request = SelectField('Funding Request', coerce=int)

class AddFamilyMemberForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    role = SelectField('Role', validators=[DataRequired()], choices=[
        ('mother', 'Mother'),
        ('child', 'Child')
    ])
    initial_balance = FloatField('Initial Balance', validators=[NumberRange(min=0)])

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
    try:
        # Check if a family with this name already exists
        if Family.query.filter_by(name=family_name).first():
            raise ValueError("A family with this name already exists")
        
        # Create new family
        family = Family(name=family_name)
        db.session.add(family)
        db.session.flush()  # This gets us the family.id
        
        # Create father user
        father = User(
            username=father_username,
            email=father_email,
            role='father',
            family_id=family.id
        )
        father.password = father_password
        db.session.add(father)
        
        try:
            db.session.commit()
            return family
        except Exception as e:
            db.session.rollback()
            print(f"Error during family creation: {str(e)}")  # Log the specific error
            raise e
            
    except Exception as e:
        print(f"Error in create_family: {str(e)}")  # Log any other errors
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
        
        if user and user.verify_password(password):
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
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')
            family_name = request.form.get('family_name')
            
            # Log received data (excluding password)
            print(f"Registration attempt - Username: {username}, Email: {email}, Role: {role}, Family: {family_name}")
            
            # Validate input
            if not all([username, email, password, role]):
                missing = []
                if not username: missing.append('username')
                if not email: missing.append('email')
                if not password: missing.append('password')
                if not role: missing.append('role')
                flash(f'Missing required fields: {", ".join(missing)}')
                return redirect(url_for('register'))
            
            if not User.validate_email(email):
                flash('Invalid email address')
                return redirect(url_for('register'))
            
            # Password complexity validation
            try:
                # Create a temporary user to test password validation
                test_user = User()
                test_user.password = password
            except ValueError as e:
                flash(str(e))
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
                print(f"ValueError during registration: {str(e)}")
                flash(str(e))
                return redirect(url_for('register'))
            except Exception as e:
                print(f"Error during registration: {str(e)}")
                flash('An error occurred. Please try again.')
                return redirect(url_for('register'))
                
        except Exception as e:
            print(f"Unexpected error during registration: {str(e)}")
            flash('An unexpected error occurred. Please try again.')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/add_transaction', methods=['GET', 'POST'])
@login_required
def add_transaction():
    form = TransactionForm()
    
    # Get active funding requests for the family
    active_requests = FundingRequest.query.filter_by(
        family_id=current_user.family_id,
        status='approved'
    ).all()
    
    # Add funding request selection to form
    form.funding_request.choices = [(0, 'General Balance (No Funding Request)')] + [(r.id, r.title) for r in active_requests]
    
    # Get family members for payee selection
    if current_user.role == 'child':
        # For children, only show parents as payee options
        family_members = User.query.filter(
            User.family_id == current_user.family_id,
            User.role.in_(['father', 'mother']),
            User.is_active == True
        ).all()
        # Auto-select the first parent
        if family_members:
            form.payee.data = family_members[0].id
    else:
        # For parents, show all family members except themselves
        family_members = User.query.filter(
            User.family_id == current_user.family_id,
            User.id != current_user.id,
            User.is_active == True
        ).all()
    
    # Update payee choices
    form.payee.choices = [(m.id, m.username) for m in family_members]
    if current_user.role != 'child':
        form.payee.choices.insert(0, (0, 'Select Payee'))
    
    if form.validate_on_submit():
        try:
            # Create new transaction
            transaction = Transaction(
                amount=form.amount.data,
                category=form.category.data,
                description=form.description.data,
                transaction_type=form.transaction_type.data,
                created_by=current_user.id,
                family_id=current_user.family_id
            )
            
            # For children, always set payee to the selected parent
            if current_user.role == 'child':
                transaction.payee_id = form.payee.data
            else:
                transaction.payee_id = form.payee.data if form.payee.data != 0 else None
            
            # Add transaction to session first to get its ID
            db.session.add(transaction)
            db.session.flush()
            
            # Handle funding request if selected
            funding_request_id = form.funding_request.data
            if funding_request_id and funding_request_id != 0:
                # Check funding request balance
                balance = FundingRequestBalance.query.filter_by(
                    funding_request_id=funding_request_id,
                    user_id=current_user.id
                ).first()
                
                if not balance:
                    flash('No balance found for this funding request.', 'danger')
                    return render_template('add_transaction.html', form=form)
                
                if balance.remaining_balance < form.amount.data:
                    flash('Insufficient funding request balance for this transaction.', 'danger')
                    return render_template('add_transaction.html', form=form)
                
                # Update funding request balance
                balance.remaining_balance -= form.amount.data
                
                # Link transaction to funding request
                fr_transaction = FundingRequestTransaction(
                    funding_request_id=funding_request_id,
                    transaction_id=transaction.id,
                    amount=form.amount.data
                )
                db.session.add(fr_transaction)
            
            # Calculate total family balance
            family_balance = sum(member.balance for member in family_members + [current_user])
            
            # Handle balance updates
            if transaction.payee_id:
                payee = User.query.get(transaction.payee_id)
                if transaction.transaction_type == 'expense':
                    if family_balance < transaction.amount:
                        flash('Insufficient family balance for this transaction.', 'danger')
                        return render_template('add_transaction.html', form=form)
                    current_user.balance -= transaction.amount
                    payee.balance += transaction.amount
                else:  # income
                    current_user.balance += transaction.amount
                    payee.balance -= transaction.amount
            else:
                # No payee selected, just update current user's balance
                if transaction.transaction_type == 'expense':
                    if family_balance < transaction.amount:
                        flash('Insufficient family balance for this transaction.', 'danger')
                        return render_template('add_transaction.html', form=form)
                    current_user.balance -= transaction.amount
                else:  # income
                    current_user.balance += transaction.amount
            
            db.session.commit()
            flash('Transaction added successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding transaction: {str(e)}', 'danger')
            return render_template('add_transaction.html', form=form)
            
    return render_template('add_transaction.html', form=form)

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
    form = AddFamilyMemberForm()
    
    if form.validate_on_submit():
        try:
            # Check if username or email already exists
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already exists')
                return redirect(url_for('add_family_member'))
                
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already exists')
                return redirect(url_for('add_family_member'))
            
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                role=form.role.data,
                family_id=current_user.family_id,
                balance=form.initial_balance.data or 0.0
            )
            new_user.password = form.password.data
            db.session.add(new_user)
            db.session.commit()
            flash(f'Successfully added new family member: {form.username.data}')
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
            
    return render_template('add_family_member.html', form=form)

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
    requests = FundingRequest.query.filter_by(
        family_id=current_user.family_id
    ).order_by(FundingRequest.created_at.desc()).all()
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

@app.route('/approve_funding_request/<int:id>', methods=['POST'])
@login_required
def approve_funding_request(id):
    if current_user.role not in ['father', 'mother']:
        flash('Only parents can approve funding requests.', 'danger')
        return redirect(url_for('funding_requests'))

    funding_request = FundingRequest.query.get_or_404(id)
    
    if funding_request.family_id != current_user.family_id:
        flash('You can only approve funding requests for your family.', 'danger')
        return redirect(url_for('funding_requests'))
    
    action = request.form.get('action', 'reject')
    
    try:
        if action == 'approve':
            # Check if family has enough balance
            requester = User.query.get(funding_request.requested_by)
            if requester.balance < funding_request.amount:
                flash('Insufficient family balance to approve this request.', 'danger')
                return redirect(url_for('funding_requests'))
            
            # Create a funding request balance record
            balance = FundingRequestBalance(
                funding_request_id=funding_request.id,
                user_id=funding_request.requested_by,
                allocated_amount=funding_request.amount,
                remaining_balance=funding_request.amount
            )
            
            # Update request status
            funding_request.status = 'approved'
            funding_request.approved_by = current_user.id
            funding_request.approved_date = datetime.utcnow()
            
            # Create initial transaction
            transaction = Transaction(
                amount=funding_request.amount,
                category='Funding Request',
                description=f'Initial allocation for: {funding_request.title}',
                transaction_type='expense',
                family_id=current_user.family_id,
                created_by=current_user.id,
                payee_id=funding_request.requested_by
            )
            
            # Link transaction to funding request
            fr_transaction = FundingRequestTransaction(
                funding_request_id=funding_request.id,
                transaction_id=transaction.id,
                amount=funding_request.amount
            )
            
            # Update balances
            requester.balance += funding_request.amount
            
            db.session.add(balance)
            db.session.add(transaction)
            db.session.add(fr_transaction)
            db.session.commit()
            
            flash(f'Funding request "{funding_request.title}" has been approved.', 'success')
        else:
            funding_request.status = 'rejected'
            funding_request.approved_by = current_user.id
            funding_request.approved_date = datetime.utcnow()
            db.session.commit()
            flash(f'Funding request "{funding_request.title}" has been rejected.', 'info')
            
    except Exception as e:
        db.session.rollback()
        flash(f'Error processing funding request: {str(e)}', 'danger')
        
    return redirect(url_for('funding_requests'))

@app.route('/funding_requests/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@father_required
def edit_funding_request(id):
    """Edit a pending funding request (father only)."""
    funding_request = FundingRequest.query.filter_by(
        id=id,
        family_id=current_user.family_id
    ).first_or_404()

    if funding_request.status != 'pending':
        flash('Only pending requests can be edited.', 'error')
        return redirect(url_for('funding_requests'))

    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount'))
            title = request.form.get('title')
            description = request.form.get('description')

            if amount <= 0:
                flash('Amount must be greater than 0.', 'error')
                return redirect(url_for('edit_funding_request', id=id))

            funding_request.amount = amount
            funding_request.title = title
            funding_request.description = description
            funding_request.updated_at = datetime.utcnow()

            db.session.commit()
            flash('Funding request updated successfully!', 'success')
            return redirect(url_for('funding_requests'))

        except ValueError:
            flash('Please enter valid values.', 'error')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')

    return render_template('edit_funding_request.html', request=funding_request)

@app.route('/funding_requests/<int:id>/delete', methods=['POST'])
@login_required
@father_required
def delete_funding_request(id):
    """Delete a pending funding request (father only)."""
    try:
        funding_request = FundingRequest.query.filter_by(
            id=id,
            family_id=current_user.family_id
        ).first_or_404()

        if funding_request.status != 'pending':
            flash('Only pending requests can be deleted.', 'error')
            return redirect(url_for('funding_requests'))

        db.session.delete(funding_request)
        db.session.commit()
        flash('Funding request deleted successfully!', 'success')

    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the request.', 'error')

    return redirect(url_for('funding_requests'))

@app.route('/dashboard')
@login_required
def dashboard():
    transactions = Transaction.query.filter_by(family_id=current_user.family_id).order_by(Transaction.created_at.desc()).all()
    
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

@app.route('/edit_family_member/<int:user_id>', methods=['GET', 'POST'])
@login_required
@father_required
def edit_family_member(user_id):
    """Edit a family member (father only)."""
    member = User.query.filter_by(id=user_id, family_id=current_user.family_id).first_or_404()
    
    # Prevent editing the father's account
    if member.role == 'father':
        flash('Cannot edit father account.', 'error')
        return redirect(url_for('manage_family_members'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            role = request.form.get('role')
            new_password = request.form.get('new_password')
            
            # Validate email format
            if not User.validate_email(email):
                flash('Invalid email format.', 'error')
                return render_template('edit_family_member.html', member=member)
            
            # Check if username or email is taken by another user
            username_exists = User.query.filter(
                User.username == username,
                User.id != user_id
            ).first()
            email_exists = User.query.filter(
                User.email == email,
                User.id != user_id
            ).first()
            
            if username_exists:
                flash('Username already taken.', 'error')
                return render_template('edit_family_member.html', member=member)
            if email_exists:
                flash('Email already registered.', 'error')
                return render_template('edit_family_member.html', member=member)
            
            # Update user details
            member.username = username
            member.email = email
            member.role = role
            
            # Update password if provided
            if new_password:
                if len(new_password) < 8:
                    flash('Password must be at least 8 characters long', 'error')
                    return render_template('edit_family_member.html', member=member)
                member.password = new_password
            
            db.session.commit()
            flash('Family member updated successfully!', 'success')
            return redirect(url_for('manage_family_members'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating the family member.', 'error')
            return render_template('edit_family_member.html', member=member)
    
    return render_template('edit_family_member.html', member=member)

@app.route('/delete_family_member/<int:user_id>')
@login_required
@father_required
def delete_family_member(user_id):
    """Delete a family member (father only)."""
    if current_user.id == user_id:
        flash('Cannot delete your own account.', 'error')
        return redirect(url_for('manage_family_members'))
    
    member = User.query.filter_by(id=user_id, family_id=current_user.family_id).first_or_404()
    
    if member.role == 'father':
        flash('Cannot delete father account.', 'error')
        return redirect(url_for('manage_family_members'))
    
    try:
        # Delete associated transactions
        Transaction.query.filter(
            (Transaction.created_by == user_id) | 
            (Transaction.payee_id == user_id)
        ).delete()
        
        # Delete associated funding requests
        FundingRequest.query.filter(
            (FundingRequest.requested_by == user_id) |
            (FundingRequest.approved_by == user_id)
        ).delete()
        
        # Delete the user
        db.session.delete(member)
        db.session.commit()
        flash('Family member deleted successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the family member.', 'error')
    
    return redirect(url_for('manage_family_members'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
