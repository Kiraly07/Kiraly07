import openai
import json
import os

# Set your OpenAI API key from environment variable
api_key = os.getenv("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")
if not api_key:
    raise ValueError("OpenAI API key is not set in the environment variable 'OPENAI_API_KEY'.")
openai.api_key = api_key

# Path to the rules.json file
RULES_FILE = "./rules.json"

def fetch_updated_rules():
    """
    Fetch updated rules from OpenAI API.
    """
    try:
        # Example prompt to fetch updated rules
        messages = [
            {
                "role": "system",
                "content": "You are an assistant that provides cybersecurity rules in JSON format."
            },
            {
                "role": "user",
                "content": (
                    "Provide updated cybersecurity rules in JSON format. "
                    "Each rule should include id, name, description, value, severity, and selected fields. "
                    "Ensure the format matches this example: "
                    "{"
                    "\"id\": \"DD001\","
                    "\"name\": \"DDoS Attack\","
                    "\"description\": \"Detects high traffic volume from multiple IPs targeting a single server, indicating a Distributed Denial of Service attack.\","
                    "\"value\": {\"threshold\": 1000, \"time_window_seconds\": 10},"
                    "\"severity\": \"Critical\","
                    "\"selected\": true"
                    "}."
                )
            }
        ]

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=1500,
            temperature=0.7
        )

        # Parse the response
        response_text = response.choices[0].message["content"].strip()
        try:
            updated_rules = json.loads(response_text)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from API response: {e}")
            print(f"Response text: {response_text}")
            return None

        return updated_rules

    except Exception as e:
        print(f"Error fetching updated rules: {e}")
        return None

def update_rules_file():
    """
    Update the rules.json file with the fetched rules.
    """
    try:
        # Fetch updated rules
        updated_rules = fetch_updated_rules()
        if not updated_rules:
            print("No updated rules fetched.")
            return

        # Load existing rules
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                try:
                    existing_rules = json.load(f)
                except json.JSONDecodeError as e:
                    print(f"Error decoding existing rules file: {e}")
                    existing_rules = []
        else:
            existing_rules = []

        # Merge or add new rules
        for updated_rule in updated_rules:
            for existing_rule in existing_rules:
                if existing_rule["id"] == updated_rule["id"]:
                    existing_rule.update(updated_rule)  # Update existing rule
                    break
            else:
                existing_rules.append(updated_rule)  # Add new rule if not found

        # Save updated rules back to the file
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(existing_rules, f, indent=4)
        
        print("Rules updated successfully.")

    except Exception as e:
        print(f"Error updating rules file: {e}")

if __name__ == "__main__":
    update_rules_file()
