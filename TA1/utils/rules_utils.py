import json

def load_rules(file_path="./rules.json"):
    """Load rules from a JSON file."""
    try:
        with open(file_path, "r", encoding="utf-8") as rules_file:
            return json.load(rules_file)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_rules(rules, file_path="./rules.json"):
    """Save rules to a JSON file."""
    try:
        with open(file_path, "w", encoding="utf-8") as rules_file:
            json.dump(rules, rules_file, indent=4)
        return True
    except Exception as e:
        print(f"Error saving rules: {e}")
        return False

def get_rule_by_index(rule_index, rules):
    """Get a rule by its index."""
    if 0 <= rule_index < len(rules):
        return rules[rule_index]
    return None

def delete_rule_by_index(rule_index, rules):
    """Delete a rule by its index."""
    if 0 <= rule_index < len(rules):
        rules.pop(rule_index)
        return True
    return False

def get_selected_attack_types(file_path="./rules.json"):
    """Get the list of selected attack types from rules.json."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            rules = json.load(f)
            return [rule['id'] for rule in rules if rule.get('selected', False)]
    except FileNotFoundError:
        print("rules.json not found. Returning an empty list.")
        return []
    except json.JSONDecodeError as e:
        print(f"Error decoding rules.json: {e}")
        return []