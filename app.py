from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import re
import yaml
from functools import wraps
import os
from datetime import datetime, timedelta
import google.generativeai as genai
from werkzeug.utils import secure_filename
from PIL import Image
import io
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FileField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)

# Configure MySQL from yaml file
db = yaml.safe_load(open('db.yaml'))
app.config['MYSQL_HOST'] = db['mysql_host']
app.config['MYSQL_USER'] = db['mysql_user']
app.config['MYSQL_PASSWORD'] = db['mysql_password']
app.config['MYSQL_DB'] = db['mysql_db']
app.config['SECRET_KEY'] = db['secret_key']

# Configure Gemini AI
GOOGLE_API_KEY = 'GOOGLE_API_KEY'
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, mode=0o750)  # Secure permissions

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Add session configuration
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session timeout

# Configure session
app.permanent_session_lifetime = timedelta(days=7)

mysql = MySQL(app)

csrf = CSRFProtect(app)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in
        if 'logged_in' not in session or not session['logged_in']:
            flash('Please login to access this page', 'error')
            # Store the requested URL in session for redirect after login
            session['next'] = request.url
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Create form classes
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

class ScanForm(FlaskForm):
    plant_image = FileField('Plant Image', validators=[DataRequired()])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user[3], password):
            session.permanent = True
            session['logged_in'] = True
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Login successful!', 'success')
            
            # Redirect to the originally requested URL if it exists
            next_page = session.pop('next', None)
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        confirm_password = form.confirm_password.data

        # Input validation
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long!', 'error')
            return redirect(url_for('register'))

        # Hash password
        hashed_password = generate_password_hash(password)

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()
        cur.close()
        
        if existing_user:
            flash('Email already exists!', 'error')
            return redirect(url_for('register'))

        # Insert new user
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
        mysql.connection.commit()
        cur.close()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

def allowed_file(filename):
    # Additional security checks
    if not '.' in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False
    return True

def analyze_plant_image(image_path):
    prompt = """
    Analyze this plant image and provide detailed information in the following format:
    1. Plant Identification:
       - Common Name: [name]
       - Scientific Name: [name]
       - Plant Family: [name]
    
    2. Disease Detection (if any):
       - Disease Name: [name]
       - Severity Level: [low/medium/high]
       - Confidence Score: [percentage]
    
    3. Causes:
       [List the main causes]
    
    4. Treatment Recommendations:
       [List the treatment steps]
    
    5. Optimal Growing Conditions:
       [List the conditions]
    
    Please provide the information in exactly this format with the exact headers for easy parsing.
    """
    
    try:
        # Load and analyze image
        image = Image.open(image_path)
        # Convert image to bytes for the new model
        image_bytes = io.BytesIO()
        image.save(image_bytes, format=image.format)
        image_parts = [
            {
                "mime_type": f"image/{image.format.lower()}",
                "data": image_bytes.getvalue()
            }
        ]
        
        # Generate content with the new model
        response = model.generate_content([prompt, image_parts[0]])
        response.resolve()
        analysis = response.text
        
        # Parse the response using string manipulation
        sections = analysis.split('\n\n')
        result = {}
        
        # Extract Plant Information
        plant_info = sections[0].split('\n')
        result['plant_name'] = plant_info[1].split(': ')[1].strip() if len(plant_info) > 1 else ''
        result['scientific_name'] = plant_info[2].split(': ')[1].strip() if len(plant_info) > 2 else ''
        
        # Extract Disease Information
        disease_info = sections[1].split('\n') if len(sections) > 1 else []
        result['disease_name'] = disease_info[1].split(': ')[1].strip() if len(disease_info) > 1 else 'No disease detected'
        result['disease_description'] = disease_info[2].split(': ')[1].strip() if len(disease_info) > 2 else ''
        confidence_text = disease_info[3].split(': ')[1].strip() if len(disease_info) > 3 else '0'
        result['confidence'] = float(confidence_text.replace('%', '')) if '%' in confidence_text else 0.0
        
        # Extract Other Information
        for section in sections:
            if section.startswith('3. Causes:'):
                result['causes'] = section.replace('3. Causes:', '').strip()
            elif section.startswith('4. Treatment Recommendations:'):
                result['treatment'] = section.replace('4. Treatment Recommendations:', '').strip()
            elif section.startswith('5. Optimal Growing Conditions:'):
                result['weather_conditions'] = section.replace('5. Optimal Growing Conditions:', '').strip()
        
        # Ensure all required fields exist
        required_fields = ['plant_name', 'scientific_name', 'disease_name', 'disease_description', 
                         'causes', 'treatment', 'weather_conditions', 'confidence']
        for field in required_fields:
            if field not in result:
                result[field] = ''
        
        return result
        
    except Exception as e:
        print(f"Error analyzing image: {e}")
        if 'analysis' in locals():
            print(f"Raw response: {analysis}")
        return None

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        if 'plant_image' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(request.url)
        file = request.files['plant_image']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            # Save uploaded file
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Analyze image using Gemini AI
            analysis_result = analyze_plant_image(filepath)
            
            if analysis_result:
                # Store scan results in database
                cur = mysql.connection.cursor()
                cur.execute("INSERT INTO scans (user_id, image_path, plant_name, scientific_name, disease_name, disease_description, causes, treatment, weather_conditions, confidence) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                            (session['user_id'], filename, analysis_result['plant_name'], analysis_result['scientific_name'], analysis_result['disease_name'], analysis_result['disease_description'], analysis_result['causes'], analysis_result['treatment'], analysis_result['weather_conditions'], analysis_result['confidence']))
                mysql.connection.commit()
                cur.close()
                
                flash('Plant analysis completed successfully!', 'success')
                return redirect(url_for('scan_result', scan_id=cur.lastrowid))
            else:
                flash('Error analyzing image', 'error')
                return redirect(request.url)
    return render_template('scan.html')

@app.route('/scan_result/<int:scan_id>')
@login_required
def scan_result(scan_id):
    # Add user verification
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
    scan = cur.fetchone()
    cur.close()
    
    if scan[1] != session['user_id']:
        flash('Access denied or scan not found', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('scan_result.html', scan=scan)

@app.route('/dashboard')
@login_required
def dashboard():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM scans WHERE user_id = %s ORDER BY scan_date DESC LIMIT 5", (session['user_id'],))
    recent_scans = cur.fetchall()
    cur.close()
    
    # Get statistics
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT
            COUNT(*) AS total_scans,
            COUNT(DISTINCT plant_name) AS unique_plants,
            COUNT(DISTINCT disease_name) AS diseases_detected
        FROM scans
        WHERE user_id = %s
    """, (session['user_id'],))
    stats = cur.fetchone()
    cur.close()
    
    return render_template('dashboard.html',
                         username=session['username'],
                         recent_scans=recent_scans,
                         stats=stats)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/', endpoint='index')
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

def init_db():
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                image_path VARCHAR(255),
                plant_name VARCHAR(100),
                scientific_name VARCHAR(100),
                disease_name VARCHAR(100),
                disease_description TEXT,
                causes TEXT,
                treatment TEXT,
                weather_conditions TEXT,
                confidence FLOAT,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        mysql.connection.commit()
        cur.close()
        print("Database tables created successfully")
    except Exception as e:
        print(f"Error creating database tables: {e}")

# Add security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Add new route handlers for footer pages
@app.route('/features')
def features():
    """Public route for features page"""
    return render_template('features.html')

@app.route('/how-it-works')
def how_it_works():
    return render_template('how_it_works.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')

# Call this when app starts
if __name__ == '__main__':
    init_db()
    app.run(debug=True) 
