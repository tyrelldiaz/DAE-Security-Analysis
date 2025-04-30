import json
import argparse
from collections import defaultdict

def load_patterns(pattern_file):
    """Loads detection patterns from a JSON file."""
    with open(pattern_file, 'r') as file:
        return json.load(file)

def load_log_file(log_file):
    """Loads log entries from a JSON-formatted log file."""
    with open(log_file, 'r') as file:
        return json.load(file)

def analyze_log(log_data, patterns):
    """Analyzes e-commerce log data using pattern rules."""
    matches = []
    user_activity = defaultdict(lambda: defaultdict(int))

    for entry in log_data:
        for pattern in patterns:
            field = pattern["field"]
            expected_value = pattern["match"]

            if field in entry and entry[field] == expected_value:
                # Handle sub-field matching
                if "sub_field" in pattern:
                    sub_field = pattern["sub_field"]
                    sub_match = pattern["sub_match"]
                    if sub_field in entry:
                        if sub_match.startswith(">"):
                            try:
                                threshold = int(sub_match[2:])
                                if entry[sub_field] > threshold:
                                    matches.append({
                                        "pattern": pattern["name"],
                                        "log_entry": entry
                                    })
                            except ValueError:
                                print(f"Invalid threshold value in pattern: {pattern['name']}")
                        elif entry[sub_field] != sub_match:
                            continue  # Skip if sub-field doesn't match
                elif pattern["name"] == "Checkout Error":
                    matches.append({
                        "pattern": pattern["name"],
                        "log_entry": entry
                    })
                else:
                  matches.append({
                        "pattern": pattern["name"],
                        "log_entry": entry
                    })

            # Handle rate limiting (High Number of Views)
            if pattern["name"] == "High Number of Views":
                user_id = entry.get("user_id")
                event = entry.get("event")
                timestamp = entry.get("timestamp")
                if user_id and event == "view_product":
                  time_window = pattern.get("time_window", 60)  # Default to 60 seconds
                  threshold = pattern.get("threshold", 10)
                  # Convert timestamp to a numerical value for comparison
                  try:
                      event_time = int(timestamp.replace('-', '').replace(':', '').replace(' ', ''))
                      user_activity[user_id]["views"] += 1
                      user_activity[user_id]["last_view_time"] = event_time

                      if user_activity[user_id]["views"] > threshold:
                          matches.append({
                              "pattern": pattern["name"],
                              "log_entry": entry,
                              "user_activity": user_activity[user_id]["views"]
                          })
                  except ValueError:
                      print(f"Invalid timestamp format: {timestamp}")
                # Clean up old activity
                for user, activity in list(user_activity.items()):
                    if "last_view_time" in activity:
                        if (int(timestamp.replace('-', '').replace(':', '').replace(' ', '')) - activity["last_view_time"]) > time_window:
                            del user_activity[user]

    return matches

def save_output(matches, output_path):
    """Saves matched log entries to a file."""
    with open(output_path, 'w') as file:
        for match in matches:
            file.write(f"Pattern: {match['pattern']}\n")
            file.write(json.dumps(match['log_entry'], indent=2))
            file.write("\n\n")

def print_summary(total_matches):
    """Prints a summary based on number of matches."""
    print(f"\n🔍 Summary: {total_matches} potential security events detected in e-commerce logs.")
    if total_matches == 0:
        print("✅ No suspicious user activity or errors detected.")
    elif total_matches < 5:
        print("⚠️  Low-risk issues found.  Review user activity and error logs.")
    else:
        print("🚨 High number of alerts!  Potential security breach or significant operational problems.  Immediate investigation needed.")
        print("Consider checking for:")
        print("-  Unusual traffic patterns (e.g., high number of failed logins, rapid product views)")
        print("-  Suspicious transactions (e.g., large quantities, unusual destinations)")
        print("-  Error trends (e.g., payment gateway failures, checkout errors)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="E-commerce Log Analyzer")
    parser.add_argument("--log", required=True, help="Path to JSON log file")
    parser.add_argument("--patterns", required=True, help="Path to detection pattern file (JSON)")
    parser.add_argument("--output", default="ecom_report.txt", help="Output report file")
    args = parser.parse_args()

    log_entries = load_log_file(args.log)
    pattern_definitions = load_patterns(args.patterns)
    found_matches = analyze_log(log_entries, pattern_definitions)
    save_output(found_matches, args.output)
    print_summary(len(found_matches))
