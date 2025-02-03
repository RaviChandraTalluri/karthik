import os
import re
import psycopg2
from psycopg2 import sql
from flask import Flask, request, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import uuid
import random
import bcrypt
import datetime
from functools import wraps
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Secure Email Credentials from environment variables
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
APP_PASSWORD = os.getenv("APP_PASSWORD")

# Database Connection
def get_connection():
    try:
        return psycopg2.connect(
            dbname="realoneinvest",
            user="karthik1",
            password="Info123tech",
            host="localhost",
            port="5433"
        )
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

# Function to create the Users table
def create_tables():
    try:
        conn = get_connection()
        if conn is None:
            print("Failed to establish database connection.")
            return

        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS Users (
            investor_id VARCHAR(20) UNIQUE,
            euid UUID PRIMARY KEY,
            first_name VARCHAR(100) NOT NULL,
            last_name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            phone_number VARCHAR(15),
            address TEXT,
            reset_token VARCHAR(255),
            otp VARCHAR(6),
            otp_expiry TIMESTAMP,
            is_verified BOOLEAN DEFAULT FALSE
        );
        """)

        conn.commit()
        cursor.close()
        conn.close()
        print("Users table created successfully.")

    except (Exception, psycopg2.Error) as error:
        print(f"Error creating tables: {error}")

# Initialize Flask app
app = Flask(__name__)

# Email validation
def is_valid_email(email):
    return re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email) is not None

# Phone number validation
def is_valid_phone_number(phone_number):
    return phone_number.isdigit() and len(phone_number) == 10

# Generate unique IDs
def generate_investor_id():
    return f"I{random.randint(1000, 9999)}"

def generate_euid():
    return str(uuid.uuid4())

# Hash passwords securely
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

# Function to send email securely
def send_email(to_email, subject, body):
    if not EMAIL_ADDRESS or not APP_PASSWORD:
        print("Email credentials not set. Please check environment variables.")
        return

    try:
        message = MIMEMultipart()
        message['From'] = EMAIL_ADDRESS
        message['To'] = to_email
        message['Subject'] = subject
        message.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, APP_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_email, message.as_string())
        print(f"Email sent successfully to {to_email}")
        server.quit()
    except smtplib.SMTPException as e:
        print(f"SMTP error: {e}")
    except Exception as e:
        print(f"General email error: {e}")

# API endpoint to store user data
@app.route('/api/signup', methods=['POST'])
def store_user():
    try:
        data = request.get_json()

        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')
        reenter_password = data.get('reenter_password')
        phone_number = data.get('phone_number')
        address = data.get('address')

        if not (first_name and last_name and email and password and reenter_password):
            return jsonify({"error": "All required fields must be provided."}), 400

        if not is_valid_email(email):
            return jsonify({"error": "Invalid email format."}), 400

        if not is_valid_phone_number(phone_number):
            return jsonify({"error": "Phone number must be exactly 10 digits."}), 400

        if password != reenter_password:
            return jsonify({"error": "Passwords do not match."}), 400

        investor_id = generate_investor_id()
        euid = generate_euid()
        password_hashed = hash_password(password)

        otp = str(random.randint(100000, 999999))
        otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)

        conn = get_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed."}), 500

        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO users (investor_id, euid, first_name, last_name, email, password, phone_number, address, otp, otp_expiry)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (investor_id, euid, first_name, last_name, email, password_hashed, phone_number, address, otp, otp_expiry))

        conn.commit()
        cursor.close()
        conn.close()

        subject = "Welcome to RealOneInvest! Verify Your Account"
        body = f"Hello {first_name},\n\nThank you for signing up with RealOneInvest!\nYour OTP for verification is: {otp}\n\nThis OTP is valid for 5 minutes."
        send_email(email, subject, body)

        return jsonify({"message": "User registered successfully. Check email for OTP."}), 201

    except (Exception, psycopg2.Error) as error:
        print(f"Error storing user data: {error}")
        return jsonify({"error": "Failed to store user data."}), 500

# API endpoint for OTP verification
@app.route('/api/verify_otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        email = data.get('email')
        otp = data.get('otp')

        if not (email and otp):
            return jsonify({"error": "Email and OTP are required."}), 400

        conn = get_connection()
        if conn is None:
            return jsonify({"error": "Database connection failed."}), 500

        cursor = conn.cursor()

        cursor.execute("""
        SELECT otp, otp_expiry FROM users WHERE email = %s
        """, (email,))
        user = cursor.fetchone()

        if user is None:
            return jsonify({"error": "User not found."}), 404

        db_otp, otp_expiry = user

        if datetime.datetime.utcnow() > otp_expiry:
            return jsonify({"error": "OTP has expired. Please request a new one."}), 400

        if db_otp != otp:
            return jsonify({"error": "Invalid OTP."}), 400

        # Update user verification status
        cursor.execute("""
        UPDATE users SET is_verified = TRUE WHERE email = %s
        """, (email,))
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({"message": "OTP verified successfully. Your account is now activated."}), 200

    except (Exception, psycopg2.Error) as error:
        print(f"Error verifying OTP: {error}")
        return jsonify({"error": "Failed to verify OTP."}), 500

# Run the app
if __name__ == '__main__':
    create_tables()
    app.run(debug=True, host="0.0.0.0", port=5000)
