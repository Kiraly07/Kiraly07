from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash  # Ensure jsonify is imported
import json
from datetime import datetime, timedelta
import subprocess
import os
import signal
import requests
import re  # Add this import for email validation
import hashlib  # Import hashlib for password hashing
from utils.telegram_utils import send_telegram_alert, configure_telegram  # Import các hàm từ file utils
from utils.rules_utils import load_rules, save_rules, get_rule_by_index, delete_rule_by_index, get_selected_attack_types
from utils.logs_utils import parse_ids_alerts_log, parse_attack_types, clear_logs


app = Flask(__name__)

# Load configuration from config.json
CONFIG_FILE = "./config.json"
try:
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config = json.load(f)
except FileNotFoundError:
    print(f"Error: {CONFIG_FILE} not found. Exiting.")
    exit(1)
except json.JSONDecodeError:
    print(f"Error: Invalid JSON format in {CONFIG_FILE}. Exiting.")
    exit(1)

# Configuration
app.secret_key = config["ids_config"].get("secret_key", "default_secret_key")
LOG_FILE = config["ids_config"].get("log_file", "./ids_alerts.log")
TELEGRAM_BOT_TOKEN = config["ids_config"]["token_telegram"]["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = config["ids_config"]["token_telegram"]["TELEGRAM_CHAT_ID"]

# Process variable to track the IDS process
ids_process = None

# Biến lưu thời gian bắt đầu IDS
ids_start_time = None

# Route to start IDS
@app.route('/start_ids', methods=['POST'])
def start_ids():
    global ids_process, ids_start_time
    if ids_process is None:
        try:
            ids_process = subprocess.Popen(
                ['python', 'ids_main.py'], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            ids_start_time = datetime.now()  # Lưu thời gian bắt đầu IDS
            return jsonify({"status": "started"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})
    return jsonify({"status": "already_running"})

# Route to stop IDS
@app.route('/stop_ids', methods=['POST'])
def stop_ids():
    global ids_process
    if ids_process is not None:
        ids_process.terminate()
        ids_process = None
        return jsonify({"status": "stopped"})
    return jsonify({"status": "not_running"})



@app.route('/')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    current_date = datetime.now().strftime("%d tháng %m năm %Y")  # Định dạng ngày
    packet_data = parse_ids_alerts_log()  # Lấy dữ liệu từ file log
    attack_data = parse_attack_types()  # Lấy dữ liệu các loại tấn công từ file log
    return render_template('dashboard.html', current_date=current_date, packet_data=packet_data, attack_data=attack_data, username=session['username'])


@app.route('/functionality')
def functionality():
    try:
        # Load rules only
        with open('./rules.json', 'r', encoding='utf-8') as f:
            rules = json.load(f)
            
        return render_template('functionality.html', 
                             rules=rules,
                             username=session.get('username'))
    except Exception as e:
        print(f"Error loading configuration: {str(e)}")
        flash('Error loading configuration', 'danger')
        return render_template('functionality.html', 
                             rules=[],
                             username=session.get('username'))

@app.route('/rules', methods=['GET', 'POST'])
def rules():
    if 'username' not in session:
        return redirect(url_for('login'))
    rules = load_rules()
    if request.method == 'POST':
        updated_rules = request.form.get('rules')
        try:
            updated_rules = json.loads(updated_rules)
            if save_rules(updated_rules):
                return redirect(url_for('rules'))
            else:
                flash('Error saving rules', 'danger')
        except json.JSONDecodeError:
            flash('Invalid JSON format', 'danger')
    current_date = datetime.now().strftime("%d/%m/%Y")
    return render_template('rules.html', rules=rules, current_date=current_date, username=session['username'])

@app.route('/rules/edit/<int:rule_index>', methods=['GET', 'POST'])
def edit_rule(rule_index):
    if 'username' not in session:
        return redirect(url_for('login'))
    rules = load_rules()
    rule = get_rule_by_index(rule_index, rules)
    if not rule:
        return render_template('error.html', message="Quy tắc không tồn tại.", username=session['username'])
    if request.method == 'POST':
        updated_rule = {
            "id": request.form.get('id'),
            "name": request.form.get('name'),
            "description": request.form.get('description'),
            "value": json.loads(request.form.get('value')),
            "severity": request.form.get('severity')
        }
        rules[rule_index] = updated_rule
        if save_rules(rules):
            return redirect(url_for('rules'))
        else:
            flash('Error saving rule', 'danger')
    return render_template('edit_rules.html', rule=rule, rule_index=rule_index, username=session['username'])

@app.route('/rules/delete/<int:rule_index>', methods=['GET'])
def delete_rule(rule_index):
    if 'username' not in session:
        return redirect(url_for('login'))
    rules = load_rules()
    if delete_rule_by_index(rule_index, rules):
        save_rules(rules)
    return redirect(url_for('rules'))

@app.route('/rules/add', methods=['GET', 'POST'])
def add_rule():
    if 'username' not in session:
        return redirect(url_for('login'))
    rules = load_rules()
    if request.method == 'POST':
        new_rule = {
            "id": request.form.get('id'),
            "name": request.form.get('name'),
            "description": request.form.get('description'),
            "value": json.loads(request.form.get('value')),
            "severity": request.form.get('severity')
        }
        rules.append(new_rule)
        if save_rules(rules):
            return redirect(url_for('rules'))
        else:
            flash('Error saving new rule', 'danger')
    return render_template('add_rule.html', username=session['username'])

@app.route('/log')
def log():
    log_file = "./ids_alerts.log"
    logs = []
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            logs = f.readlines()
    except FileNotFoundError:
        logs = ["Log file not found."]
    except Exception as e:
        logs = [f"Error reading log file: {e}"]

    return render_template('log.html', logs=logs, username=session.get('username', 'Guest'))

@app.route('/login', methods=['POST', 'GET'])
def login():
    """Login route to authenticate users using credentials from config.json."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Hash the entered password
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Validate credentials from config.json
        for account in config["ids_config"]["admin_accounts"]:
            if account["username"] == username and account["password_hash"] == password_hash:
                session['username'] = username
                return redirect(url_for('dashboard'))

        # If no match, return error
        return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/configure_telegram', methods=['POST'])
def configure_telegram_route():
    """Route to configure Telegram bot."""
    bot_token = request.form.get('bot_token')
    chat_id = request.form.get('chat_id')

    if configure_telegram(bot_token, chat_id):
        return redirect(url_for('functionality'))
    else:
        return "Error saving Telegram configuration", 500

def send_alert(rule_id, attack_name, src_ip, details="", severity="Medium"):
    """Send alert through Telegram only."""
    selected_types = get_selected_attack_types()
    if rule_id not in selected_types:
        print(f"[INFO] Attack type {rule_id} not selected for alerts.")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"""
    Time: {timestamp}
    Rule ID: {rule_id}
    Attack Name: {attack_name}
    Source IP: {src_ip}
    Severity: {severity}
    
    Additional Details:
    {details}
    """
    
    # Send Telegram alert
    try:
        print(f"[DEBUG] Sending Telegram alert: {message}")  # Debug message
        send_telegram_alert(message)
        print(f"[SUCCESS] Telegram alert sent for Rule ID: {rule_id}.")  # Debug message
    except Exception as e:
        print(f"[ERROR] Failed to send Telegram alert: {str(e)}")
        print(f"[DEBUG] Check TELEGRAM_BOT_TOKEN: {TELEGRAM_BOT_TOKEN} and TELEGRAM_CHAT_ID: {TELEGRAM_CHAT_ID}")  # Debug info

@app.route('/clear_logs', methods=['POST'])
def clear_logs_route():
    if clear_logs():
        return jsonify({'success': True, 'message': 'Logs cleared successfully'})
    else:
        return jsonify({'success': False, 'message': 'Error clearing logs'}), 500

@app.route('/update_attack_types', methods=['POST'])
def update_attack_types():
    try:
        selected_attack_types = request.form.getlist('attack_types')
        
        # Read current rules
        with open('./rules.json', 'r', encoding='utf-8') as f:
            rules = json.load(f)
        
        # Update selected status for each rule
        for rule in rules:
            rule['selected'] = rule['id'] in selected_attack_types
        
        # Save updated rules
        with open('./rules.json', 'w', encoding='utf-8') as f:
            json.dump(rules, f, indent=4)
        
        # Reflect updated rules in the attack types
        attack_types = [
            {
                "id": rule["id"],
                "name": rule["name"],
                "description": rule["description"],
                "severity": rule["severity"],
                "selected": rule["selected"]
            }
            for rule in rules
        ]
        
        print("[SUCCESS] Attack types updated successfully.")
        flash('Attack types updated successfully!', 'success')  # Add flash message
        return render_template('functionality.html', rules=attack_types, username=session.get('username'))
        
    except Exception as e:
        print(f"[ERROR] Error updating attack types: {str(e)}")
        flash('Error updating attack types', 'danger')  # Add error flash message
        return redirect(url_for('functionality'))  # Redirect to functionality page

@app.route('/dashboard_data', methods=['GET'])
def dashboard_data():
    try:
        log_file = LOG_FILE
        total_packets = 0
        total_attacks = 0
        today = datetime.now().strftime("%Y-%m-%d")

        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if today in line:
                        total_packets += 1
                        if "[ALERT]" in line:
                            total_attacks += 1

        uptime = "00:00:00"
        if ids_start_time:
            elapsed = datetime.now() - ids_start_time
            uptime = str(timedelta(seconds=elapsed.total_seconds())).split(".")[0]

        return jsonify({
            "total_packets": total_packets,
            "total_attacks": total_attacks,
            "uptime": uptime
        })
    except Exception as e:
        print(f"Error fetching dashboard data: {e}")
        return jsonify({"error": "Failed to fetch dashboard data"}), 500

@app.route('/monthly_packet_data', methods=['GET'])
def monthly_packet_data():
    try:
        log_file = "./ids_alerts.log"
        monthly_data = {month: 0 for month in range(1, 13)}

        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        log_date = datetime.strptime(line.split()[0], "[%Y-%m-%d")
                        month = log_date.month
                        monthly_data[month] += 1
                    except Exception as e:
                        print(f"Error parsing log line: {line}, {e}")

        labels = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        data = [monthly_data[month] for month in range(1, 13)]

        return jsonify({"labels": labels, "data": data})
    except Exception as e:
        print(f"Error fetching monthly packet data: {e}")
        return jsonify({"error": "Failed to fetch monthly packet data"}), 500

@app.route('/save-email-recipients', methods=['POST'])
def save_email_recipients():
    """Remove this route as email functionality is no longer supported."""
    return jsonify({'success': False, 'message': 'Email functionality removed'}), 400

@app.route('/update_rules', methods=['POST'])
def update_rules():
    """
    Route to execute the update_rules.py script to update rules.json.
    """
    try:
        result = subprocess.run(
            ['python', config["ids_config"].get("update_script_path", "e:\\TA1\\update_rules.py")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            flash('Rules updated successfully!', 'success')
        else:
            flash(f'Error updating rules: {result.stderr}', 'danger')
    except Exception as e:
        flash(f'Error executing update script: {str(e)}', 'danger')
    return redirect(url_for('rules'))

if __name__ == '__main__':
    app.run(debug=config["ids_config"].get("debug_mode", True))