# ========================================
# SECURE TASK TRACKER - FLASK APPLICATION
# Built for software engineering apprenticeship portfolio
# ========================================
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Create Flask application instance
app = Flask(__name__)

# Configuration - SECRET_KEY required for session security
app.config['SECRET_KEY'] = 'task-tracker-secret-key-2026-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'  # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking

# Initialize database and login manager
db = SQLAlchemy(app)  # SQLAlchemy for database operations
login_manager = LoginManager()  # Flask-Login for user authentication
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page if not authenticated

# ========================================
# DATABASE MODELS
# ========================================

# User model - stores username and hashed password
class User(UserMixin, db.Model):
    """
    User database table
    - id: Primary key (auto-generated)
    - username: Unique username (max 80 chars)
    - password_hash: Securely hashed password
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

# Task model - stores user tasks
class Task(db.Model):
    """
    Task database table
    - id: Primary key (auto-generated)
    - title: Task title (max 100 chars)
    - description: Optional task description
    - completed: Boolean - task done/undone
    - user_id: Foreign key linking to User table
    """
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)  # Text field for longer descriptions
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Load user function required by Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Retrieve user from database by ID"""
    return User.query.get(int(user_id))

# ========================================
# ROUTES - WEB PAGE ENDPOINTS
# ========================================

@app.route('/')
def index():
    """Redirect root URL to login page"""
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration"""
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        
        # Check if username already exists
        if not User.query.filter_by(username=username).first():
            # Create new user
            user = User(username=username, password_hash=password)
            db.session.add(user)
            db.session.commit()
            flash('Registered successfully! Please login.')
            return redirect(url_for('login'))
        flash('Username already exists. Choose another.')
    
    # Show registration form (GET request)
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if request.method == 'POST':
        # Find user by username
        user = User.query.filter_by(username=request.form['username']).first()
        
        # Verify password and login
        if user and check_password_hash(user.password_hash, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.')
    
    # Show login form (GET request)
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user and redirect to login"""
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Show user's task dashboard"""
    # Get all tasks for current user only
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', tasks=tasks)

@app.route('/add', methods=['POST'])
@login_required
def add_task():
    """Add new task for current user"""
    # Create task from form data
    task = Task(
        title=request.form['title'], 
        description=request.form['description'], 
        user_id=current_user.id
    )
    db.session.add(task)
    db.session.commit()
    flash('Task added successfully!')
    return redirect(url_for('dashboard'))

@app.route('/toggle/<int:task_id>')
@login_required
def toggle_task(task_id):
    """Mark task as complete/incomplete"""
    task = Task.query.get_or_404(task_id)
    
    # Security: Only allow user to modify their own tasks
    if task.user_id == current_user.id:
        task.completed = not task.completed
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    """Delete user's task"""
    task = Task.query.get_or_404(task_id)
    
    # Security: Only allow user to delete their own tasks
    if task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('dashboard'))

# ========================================
# START APPLICATION
# ========================================
if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    # Run development server
    app.run(debug=True)
