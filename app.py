from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
import os
import json
import requests
from dotenv import load_dotenv
from datetime import timedelta

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///healthamity.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads', 'profile_pics')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size



# OpenRouter Configuration
OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY')
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"

def get_ai_health_response(query):
    """Get health analysis using OpenRouter's Deepseek model"""
    try:
        # Prepare the system prompt for medical analysis
        system_prompt = """You are a knowledgeable AI Health Assistant. Your task is to analyze the symptoms provided and give a detailed, structured response. For each query, provide:

1. POSSIBLE CONDITIONS:
   - List potential conditions from most to least likely
   - Include brief explanations for why each condition matches the symptoms

2. HOME CARE RECOMMENDATIONS:
   - Specific steps for symptom management
   - Lifestyle modifications if applicable
   - Diet and rest recommendations

3. MEDICATION SUGGESTIONS:
   - Relevant over-the-counter medications
   - Proper dosage guidelines
   - Potential side effects to watch for

4. WARNING SIGNS:
   - Red flags that require immediate medical attention
   - Symptoms that indicate worsening condition
   - Timeline for when to seek professional help

Remember to:
- Maintain a professional and clear communication style
- Emphasize that this is not a substitute for professional medical diagnosis
- Encourage seeking medical attention when appropriate
- Be specific but avoid absolute diagnostic statements"""

        # Prepare the API request
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "HTTP-Referer": "https://healthamity.com",
            "Content-Type": "application/json"
        }

        data = {
            "model": "mistralai/mistral-7b-instruct",  # Using Mistral model
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze these symptoms and provide a detailed response following the structured format: {query}"}
            ],
            "temperature": 0.7,
            "max_tokens": 1500,
            "top_p": 0.9
        }

        # Make the API request with increased timeout
        response = requests.post(OPENROUTER_API_URL, headers=headers, json=data, timeout=60)
        
        if response.status_code == 401:
            app.logger.error("OpenRouter API authentication failed. Check API key.")
            return None
        elif response.status_code == 404:
            app.logger.error("Model not found. Check model name.")
            return None
        elif not response.ok:
            app.logger.error(f"OpenRouter API error: {response.text}")
            return None

        # Extract and format the response
        result = response.json()
        if result and 'choices' in result and len(result['choices']) > 0:
            response_text = result['choices'][0]['message']['content']
            
            # Add a clear disclaimer at the end
            disclaimer = "\n\n⚠️ IMPORTANT DISCLAIMER:\nThis information is for educational purposes only and should not be considered medical advice. Always consult with a qualified healthcare provider for proper diagnosis and treatment."
            
            return response_text + disclaimer
            
        return None

    except requests.exceptions.Timeout:
        app.logger.error("Request to OpenRouter API timed out")
        return None
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Request error: {str(e)}")
        return None
    except Exception as e:
        app.logger.error(f"Error in AI health response: {str(e)}")
        return None

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    profile_photo = db.Column(db.String(200))
    health_records = db.relationship('HealthRecord', backref='user', lazy=True)

class HealthRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    blood_pressure = db.Column(db.String(20))
    blood_sugar = db.Column(db.Float)
    heart_rate = db.Column(db.Integer)
    notes = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and password == user.password:  # In production, use proper password hashing
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password!', 'danger')
    return render_template('login.html', title='Login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', title='Dashboard')

@app.route('/health-monitoring')
@login_required
def health_monitoring():
    records = HealthRecord.query.filter_by(user_id=current_user.id).order_by(HealthRecord.date.desc()).all()
    
    # Prepare records for JSON serialization
    records_json = []
    for record in records:
        records_json.append({
            'date': record.date.strftime('%Y-%m-%d %H:%M'),
            'blood_pressure': record.blood_pressure,
            'blood_sugar': record.blood_sugar,
            'heart_rate': record.heart_rate,
            'notes': record.notes
        })
    
    return render_template('health_monitoring.html', 
                         title='Health Monitoring',
                         records=records,
                         records_json=json.dumps(records_json))

@app.route('/add-health-record', methods=['POST'])
@login_required
def add_health_record():
    data = request.json
    
    # Validate blood pressure format (e.g., "120/80")
    blood_pressure = data.get('blood_pressure')
    if blood_pressure:
        try:
            systolic, diastolic = map(int, blood_pressure.split('/'))
            if not (60 <= systolic <= 200 and 40 <= diastolic <= 130):
                return jsonify({'error': 'Invalid blood pressure values'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid blood pressure format'}), 400
    
    # Validate blood sugar
    blood_sugar = data.get('blood_sugar')
    if blood_sugar:
        try:
            blood_sugar = float(blood_sugar)
            if not (30 <= blood_sugar <= 600):
                return jsonify({'error': 'Invalid blood sugar value'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid blood sugar format'}), 400
    
    # Validate heart rate
    heart_rate = data.get('heart_rate')
    if heart_rate:
        try:
            heart_rate = int(heart_rate)
            if not (30 <= heart_rate <= 220):
                return jsonify({'error': 'Invalid heart rate value'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid heart rate format'}), 400
    
    record = HealthRecord(
        user_id=current_user.id,
        blood_pressure=blood_pressure if blood_pressure else None,
        blood_sugar=blood_sugar if blood_sugar else None,
        heart_rate=heart_rate if heart_rate else None,
        notes=data.get('notes')
    )
    
    db.session.add(record)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/ai-chat')
@login_required
def ai_chat():
    return render_template('ai_chat.html', title='AI Health Assistant')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='Profile')

@app.route('/upload-profile-picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('profile'))
    
    file = request.files['profile_picture']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('profile'))
    
    if file and allowed_file(file.filename):
        # Delete old profile picture if it exists
        if current_user.profile_photo:
            old_file = os.path.join(app.root_path, current_user.profile_photo.lstrip('/'))
            if os.path.exists(old_file):
                os.remove(old_file)
        
        # Save new profile picture
        filename = secure_filename(f"user_{current_user.id}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        full_path = os.path.join(app.root_path, filepath)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        file.save(full_path)
        
        # Update database
        current_user.profile_photo = '/' + filepath.replace('\\', '/')
        db.session.commit()
        
        flash('Profile picture updated successfully!', 'success')
    else:
        flash('Invalid file type. Please use PNG, JPG, JPEG, or GIF.', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    name = request.form.get('name')
    email = request.form.get('email')
    new_password = request.form.get('new_password')
    
    if not name or not email:
        flash('Name and email are required', 'danger')
        return redirect(url_for('profile'))
    
    # Check if email is taken by another user
    existing_user = User.query.filter(User.email == email, User.id != current_user.id).first()
    if existing_user:
        flash('Email already taken', 'danger')
        return redirect(url_for('profile'))
    
    current_user.name = name
    current_user.email = email
    
    if new_password:
        current_user.password = new_password  # In production, hash the password
    
    db.session.commit()
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    user_message = request.json.get('message', '').lower()
    
    # Check for emergency keywords
    emergency_keywords = ['chest pain', 'difficulty breathing', 'stroke', 'unconscious', 'severe bleeding',
                         'heart attack', 'seizure', 'head injury', 'overdose', 'suicide', 'poisoning',
                         'severe allergic reaction', 'anaphylaxis', 'severe burn']
    
    for keyword in emergency_keywords:
        if keyword in user_message:
            return jsonify({
                'message': '🚨 EMERGENCY MEDICAL SITUATION DETECTED!\n\n'
                          'IMMEDIATE ACTION REQUIRED:\n'
                          '1. Call Emergency Services (911) NOW\n'
                          '2. Go to the nearest Emergency Room\n'
                          '3. If available, call for immediate medical assistance\n\n'
                          '⚠️ DO NOT WAIT or rely on this app for emergency situations!',
                'warning': 'This is a potentially life-threatening condition requiring immediate professional medical attention.'
            })
    
    try:
        # Get AI analysis of symptoms
        ai_response = get_ai_health_response(user_message)
        
        if ai_response:
            return jsonify({
                'message': ai_response,
                'warning': '⚠️ This analysis is for informational purposes only. If symptoms persist or worsen, please consult with a qualified healthcare provider immediately.'
            })
        else:
            return jsonify({
                'message': '🏥 I apologize, but I am unable to provide a proper analysis at this moment.\n\n'
                          'For your safety and well-being, please:\n'
                          '1. Document your symptoms\n'
                          '2. Contact your healthcare provider\n'
                          '3. Visit an urgent care center if needed\n'
                          '4. Monitor your symptoms for any changes',
                'warning': 'If you feel your symptoms are severe or life-threatening, do not wait - seek immediate medical attention.'
            })
        
    except Exception as e:
        app.logger.error(f"Error in health chat: {str(e)}")
        return jsonify({
            'message': 'An error occurred while analyzing your symptoms. For your safety, please consult with a healthcare provider.',
            'warning': 'If you need immediate medical assistance, contact emergency services or your healthcare provider.'
        }), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return render_template('register.html', title='Register')
        
        user = User(name=name, email=email, password=password)  # In production, hash the password
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
