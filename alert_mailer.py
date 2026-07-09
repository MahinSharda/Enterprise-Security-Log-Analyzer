import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv
from ai_analyst import generate_threat_analysis

# Securely load environment variables
load_dotenv()

# Fetch credentials from .env
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
APP_PASSWORD = os.getenv("EMAIL_PASSWORD")
RECEIVER_EMAIL = os.getenv("SENDER_EMAIL") # Sending alert to yourself for now

def send_security_alert(user_id, action, resource, location, time_str="Unknown"):
    """
    Sends a secure email alert containing the AI-generated threat analysis.
    """
    if not SENDER_EMAIL or not APP_PASSWORD:
        print("❌ Error: Email credentials not found in .env file.")
        return False

    try:
        print("🤖 Generating AI Threat Analysis for the email...")
        ai_report = generate_threat_analysis(user_id, action, resource, location, time_str)
        
        # Create the email content
        subject = f"🚨 AI SECURITY ALERT: Suspicious Activity for {user_id}"
        
        body = f"""
        Enterprise Security System has detected a critical anomaly.
        
        --- AI THREAT ANALYSIS ---
        {ai_report}
        
        --- EVENT DETAILS ---
        - Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        - User ID: {user_id}
        - Action Attempted: {action}
        - Resource: {resource}
        - Location: {location}
        
        Please investigate this activity immediately via the Security Dashboard.
        
        Automated AI Alert System
        """
        
        # Setup the MIME
        message = MIMEMultipart()
        message['From'] = SENDER_EMAIL
        message['To'] = RECEIVER_EMAIL
        message['Subject'] = subject
        message.attach(MIMEText(body, 'plain'))
        
        # Connect to Gmail SMTP server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        text = message.as_string()
        
        # Send email and close connection
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, text)
        server.quit()
        
        print("✅ AI Alert Email Sent Successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error sending email: {e}")
        return False

# --- TESTING ---
if __name__ == "__main__":
    print("Testing Secure AI Email Alert System...")
    send_security_alert("user_003", "view", "encryption_keys.dat", "New York", "01:32 AM")