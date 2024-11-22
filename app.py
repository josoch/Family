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
    transactions = db.relationship('Transaction', backref='family_ref', lazy=True)
    funding_requests = db.relationship('FundingRequest', backref='family_ref', lazy=True)

class Transaction(db.Model):
    __tablename__ = 'financial_transaction'
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    transaction_type = db.Column(db.String(20), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payee_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # Relationships without backrefs (since they're defined in User model)
    creator = db.relationship('User', foreign_keys=[created_by])
    payee = db.relationship('User', foreign_keys=[payee_id])

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)  # father, mother, child
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    is_active = db.Column(db.Boolean, default=True)

    # Define relationships with backrefs here
    transactions_created = db.relationship('Transaction', 
                                         foreign_keys='Transaction.created_by',
                                         backref=db.backref('creator_ref', lazy=True),
                                         lazy=True)
    transactions_received = db.relationship('Transaction', 
                                          foreign_keys='Transaction.payee_id',
                                          backref=db.backref('payee_ref', lazy=True),
                                          lazy=True)
    requests_created = db.relationship('FundingRequest', 
                                     foreign_keys='FundingRequest.requested_by',
                                     backref=db.backref('requester_ref', lazy=True),
                                     lazy=True)
    requests_approved = db.relationship('FundingRequest',
                                      foreign_keys='FundingRequest.approved_by',
                                      backref=db.backref('approver_ref', lazy=True),
                                      lazy=True)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
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
    status = db.Column(db.String(20), default='pending')
    requested_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'), nullable=False)
    comments = db.Column(db.Text)
    date_requested = db.Column(db.DateTime, server_default=db.text('CURRENT_TIMESTAMP'))
    approved_date = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, server_default=db.text('CURRENT_TIMESTAMP'), 
                          onupdate=db.text('CURRENT_TIMESTAMP'))

    # Relationships without backrefs (since they're defined in User model)
    requester = db.relationship('User', foreign_keys=[requested_by])
    approver = db.relationship('User', foreign_keys=[approved_by])

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
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        family_name = request.form.get('family_name')
        
        # Validate input
        if not all([username, email, password, role]):
            flash('All fields are required')
            return redirect(url_for('register'))
        
        if not User.validate_email(email):
            flash('Invalid email address')
            return redirect(url_for('register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long')
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
    form = TransactionForm()
    
    # Get family members for payee selection (excluding current user)
    family_members = User.query.filter(
        User.family_id == current_user.family_id,
        User.id != current_user.id,
        User.is_active == True
    ).all()
    
    # Update payee choices
    form.payee.choices = [(m.id, m.username) for m in family_members]
    form.payee.choices.insert(0, (0, 'Select Payee'))  # Add default option
    
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
            
            # Set payee if selected
            if form.payee.data != 0:  # 0 is our "Select Payee" option
                transaction.payee_id = form.payee.data
                
                # Update balances based on transaction type
                payee = User.query.get(form.payee.data)
                if transaction.transaction_type == 'expense':
                    # Current user pays money to payee
                    if current_user.balance < transaction.amount:
                        flash('Insufficient balance for this transaction.', 'danger')
                        return render_template('add_transaction.html', form=form)
                    current_user.balance -= transaction.amount
                    payee.balance += transaction.amount
                else:  # income
                    # Current user receives money from payee
                    if payee.balance < transaction.amount:
                        flash('Selected payee has insufficient balance.', 'danger')
                        return render_template('add_transaction.html', form=form)
                    current_user.balance += transaction.amount
                    payee.balance -= transaction.amount
            else:
                # No payee selected, just update current user's balance
                if transaction.transaction_type == 'expense':
                    if current_user.balance < transaction.amount:
                        flash('Insufficient balance for this transaction.', 'danger')
                        return render_template('add_transaction.html', form=form)
                    current_user.balance -= transaction.amount
                else:  # income
                    current_user.balance += transaction.amount
            
            db.session.add(transaction)
            db.session.commit()
            flash('Transaction added successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding transaction: {str(e)}', 'danger')
            
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
            
        if not User.validate_email(email):
            flash('Invalid email address')
            return redirect(url_for('add_family_member'))
            
        if len(password) < 8:
            flash('Password must be at least 8 characters long')
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
            new_user.password = password
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
    requests = FundingRequest.query.filter_by(
        family_id=current_user.family_id
    ).order_by(FundingRequest.date_requested.desc()).all()
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
        amount = float(request.form.get('amount', 0))

        if status not in ['approved', 'rejected']:
            flash('Invalid status provided.', 'error')
            return redirect(url_for('funding_requests'))

        if amount <= 0:
            flash('Amount must be greater than 0.', 'error')
            return redirect(url_for('funding_requests'))

        # Update request
        funding_request.status = status
        funding_request.approved_by = current_user.id
        funding_request.approved_date = datetime.utcnow()
        funding_request.comments = comments
        funding_request.amount = amount  # Update with potentially modified amount

        # If approved, create a transaction and update requester's balance
        if status == 'approved':
            # Update requester's balance
            requester = User.query.get(funding_request.requested_by)
            requester.balance += amount
            
            # Create transaction
            transaction = Transaction(
                amount=amount,
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

    except ValueError:
        db.session.rollback()
        flash('Invalid amount provided.', 'error')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while processing the request. Please try again.', 'error')

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
