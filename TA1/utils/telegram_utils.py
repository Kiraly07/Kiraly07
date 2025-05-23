import json
import requests

def send_telegram_alert(message, config_path="config.json"):
    """Send an alert message to Telegram."""
    try:
        with open(config_path, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)
        bot_token = config["ids_config"]["token_telegram"].get("TELEGRAM_BOT_TOKEN")
        chat_id = config["ids_config"]["token_telegram"].get("TELEGRAM_CHAT_ID")
        if not bot_token or not chat_id:
            print("[ERROR] Telegram configuration is missing.")
            print(f"[DEBUG] TELEGRAM_BOT_TOKEN: {bot_token}, TELEGRAM_CHAT_ID: {chat_id}")  # Debug message
            return

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message
        }
        print(f"[DEBUG] Sending Telegram message to chat_id {chat_id}...")  # Debug message
        response = requests.post(url, json=payload)
        print(f"[DEBUG] Telegram API response: {response.status_code} - {response.text}")  # Debug message
        if response.status_code == 200:
            print("[SUCCESS] Telegram message sent successfully.")  # Debug message
        else:
            print(f"[ERROR] Failed to send Telegram message. Response: {response.json()}")  # Log full response
    except FileNotFoundError:
        print("[ERROR] Configuration file not found.")
    except KeyError as e:
        print(f"[ERROR] Missing key in configuration: {e}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Network error while sending Telegram message: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error sending Telegram message: {e}")

def configure_telegram(bot_token, chat_id, config_path="config.json"):
    """Save Telegram bot configuration."""
    try:
        with open(config_path, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)
        config["ids_config"]["token_telegram"]["TELEGRAM_BOT_TOKEN"] = bot_token
        config["ids_config"]["token_telegram"]["TELEGRAM_CHAT_ID"] = chat_id
        with open(config_path, "w", encoding="utf-8") as config_file:
            json.dump(config, config_file, indent=4)
        print("Telegram configuration saved successfully.")  # Debug message
        return True
    except FileNotFoundError:
        print("[ERROR] Configuration file not found.")
    except KeyError as e:
        print(f"[ERROR] Missing key in configuration: {e}")
    except Exception as e:
        print(f"[ERROR] Error saving Telegram configuration: {e}")
        return False