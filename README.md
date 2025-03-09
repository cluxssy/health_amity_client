# HealthAmity - Health Monitoring System

HealthAmity is a modern web application for tracking and monitoring personal health metrics. It provides an intuitive interface for users to record and visualize their health data, including blood pressure, blood sugar, and heart rate measurements.

## Features

- **User Authentication System**
  - Secure login and registration
  - Profile management with photo upload
  - Password protection and session management

- **Health Metrics Monitoring**
  - Track blood pressure
  - Monitor blood sugar levels
  - Record heart rate
  - Add notes to health records

- **Data Visualization**
  - Interactive charts for all health metrics
  - Historical data tracking
  - Trend analysis

- **Modern UI/UX**
  - Responsive design
  - Real-time updates
  - Interactive dashboard
  - Clean and intuitive interface

- **AI Health Assistant**
  - Get AI-powered health insights
  - Symptom analysis
  - Health recommendations

## Installation

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd healthamity
   ```

2. **Create a Virtual Environment**
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # Linux/Mac
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Setup**
   Create a `.env` file in the root directory with the following variables:
   ```
   FLASK_SECRET_KEY=your_secret_key_here
   OPENROUTER_API_KEY=your_openrouter_api_key_here
   ```

5. **Initialize the Database**
   ```bash
   # Start Python shell
   python
   >>> from app import app, db
   >>> with app.app_context():
   >>>     db.create_all()
   >>> exit()
   ```

6. **Run the Application**
   ```bash
   python app.py
   ```
   The application will be available at `http://localhost:5000`

## Project Structure

```
healthamity/
├── app.py                 # Main application file
├── requirements.txt       # Project dependencies
├── .env                  # Environment variables
├── static/               # Static files (CSS, JS, images)
│   ├── uploads/         # User uploaded files
│   └── profile_pics/    # Profile pictures
└── templates/           # HTML templates
    ├── base.html        # Base template
    ├── dashboard.html   # Dashboard template
    ├── login.html       # Login template
    └── health_monitoring.html  # Health monitoring template
```

## Usage

1. **Registration/Login**
   - Create a new account or login with existing credentials
   - Upload a profile picture (optional)

2. **Health Monitoring**
   - Navigate to the Health Monitoring page
   - Enter new health measurements
   - View historical data in charts
   - Add notes to your records

3. **Dashboard**
   - View quick statistics
   - Access all features
   - Get health insights

4. **Profile Management**
   - Update profile information
   - Change profile picture
   - Manage account settings

## Technical Requirements

- Python 3.8 or higher
- SQLite database
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Internet connection for CDN resources (Bootstrap, Chart.js)

## Security Features

- Password hashing
- Secure session management
- CSRF protection
- File upload validation
- Input sanitization

## Browser Compatibility

- Google Chrome (recommended)
- Mozilla Firefox
- Microsoft Edge
- Safari

## Support

For support, please contact:
- Email: support@healthamity.com
- Website: www.healthamity.com

## License

This project is licensed under the MIT License - see the LICENSE file for details.
