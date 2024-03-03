import json
import sys

def check_severity(data, level=0):
    if level > 2 or not isinstance(data, dict):
        return

    for key, value in data.items():
        if key == 'matches' and isinstance(value, list):
            for match in value:
                if isinstance(match, dict) and 'vulnerability' in match:
                    vulnerability = match['vulnerability']
                    if 'severity' not in vulnerability:
                        #print(f"Severity missing for the following match:\n{json.dumps(match, indent=2)}")
                        vulnerability['severity'] = 'Unknown'
                    else:
                        pass
                        #print(f"Severity for match: {vulnerability['severity']}")
        elif isinstance(value, dict):
            check_severity(value, level + 1)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    check_severity(item, level + 1)

if len(sys.argv) != 2:
    print("Usage: python severity_fixer.py <json_file>")
    sys.exit(1)

file_path = sys.argv[1]
with open(file_path, 'r') as file:
    json_data = json.load(file)

# Add Unknown severity for missing severity in each match
check_severity(json_data)

with open(file_path, 'w') as file:
    json.dump(json_data, file, indent=2)
