from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
# Admin-only decorator (if not already defined)
from functools import wraps
from flask import abort

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default='user')  # For admin support
    todos = db.relationship('Todo', backref='user', lazy=True)


class Todo(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Role-required decorator
def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# Routes
@app.route('/')
@login_required
def home():
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of tasks per page
    todos = Todo.query.filter_by(user_id=current_user.id).order_by(Todo.date_created.desc()).paginate(page=page, per_page=5)
    return render_template('index.html', allTodo=todos)



@app.route('/add', methods=['POST'])
@login_required
def add():
    title = request.form['title']
    desc = request.form['description']
    todo = Todo(title=title, description=desc, user_id=current_user.id)
    db.session.add(todo)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/delete/<int:sno>')
@login_required
def delete(sno):
    todo = Todo.query.get_or_404(sno)
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/update/<int:sno>', methods=['GET', 'POST'])
@login_required
def update(sno):
    todo = Todo.query.get_or_404(sno)
    if request.method == 'POST':
        todo.title = request.form['title']
        todo.description = request.form['description']
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('update.html', todo=todo)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        # Assign role: admin if username is 'admin', else user
        role = 'admin' if username.lower() == 'admin' else 'user'
        user = User(username=username, password=password, role=role)

        db.session.add(user)
        db.session.commit()
        flash('Registered successfully! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            flash('Login successful!', 'success')
            # 👇 Role-based redirect
            if user.role == 'admin':
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('home'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Admin-only page
@app.route('/admin')
@login_required
def admin():
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of tasks per page
    allTodo = Todo.query.order_by(Todo.date_created.desc()).paginate(page=page, per_page=10)
    tasks = Todo.query.order_by(Todo.date_created.desc()).all()
    users = User.query.all()
    return render_template('admin.html', users=users, allTodo=allTodo,tasks=tasks)


# Admin: Create new user
@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
        else:
            hashed_pw = generate_password_hash(password)
            new_user = User(username=username, password=hashed_pw, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully.', 'success')
            return redirect(url_for('admin'))
    return render_template('admin_add_user.html')

# Admin: Edit existing user
@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])
        user.role = request.form['role']
        db.session.commit()
        flash('User details updated.', 'success')
        return redirect(url_for('admin'))
    return render_template('admin_edit_user.html', user=user)

# 403 error handler
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

# Delete user (admin only)
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash("Cannot delete another admin.", 'danger')
        return redirect(url_for('admin'))
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully.", 'success')
    return redirect(url_for('admin'))

@app.route('/admin/update/<int:sno>', methods=['GET', 'POST'])
@admin_required
def update_task_admin(sno):
    todo = Todo.query.get_or_404(sno)
    if request.method == 'POST':
        todo.title = request.form['title']
        todo.description = request.form['description']
        db.session.commit()
        flash('Task updated by admin.', 'success')
        return redirect(url_for('admin'))
    return render_template('admin_edit_task.html', todo=todo)

@app.route('/admin/delete/<int:sno>')
@admin_required
def delete_task_admin(sno):
    todo = Todo.query.get_or_404(sno)
    db.session.delete(todo)
    db.session.commit()
    flash('Task deleted by admin.', 'info')
    return redirect(url_for('admin'))


# Change user role
@app.route('/admin/change_role/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def change_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role in ['admin', 'user']:
        user.role = new_role
        db.session.commit()
        flash(f"Role for {user.username} changed to {new_role}.", 'success')
    else:
        flash("Invalid role.", 'danger')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
