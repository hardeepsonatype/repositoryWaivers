import requests
import csv
from datetime import datetime

# Configuration
IQ_SERVER_URL = 'http://localhost:8070'  # Replace with your IQ Server URL
API_ENDPOINT = f'{IQ_SERVER_URL}/api/v2/reports/components/waivers'
AUTH = ('admin', 'admin123')  # Replace with your username and password
OUTPUT_CSV = 'repository_waivers.csv'

# Function to fetch waivers
def fetch_waivers():
    response = requests.get(API_ENDPOINT, auth=AUTH)
    response.raise_for_status()
    data = response.json()
    #print(data)  # Print full response to debug
    return data

def format_timestamp(timestamp):
    if not timestamp or timestamp == "N/A":
        return "N/A"
    
    try:
        # Remove timezone offset (+0000) and parse
        dt = datetime.strptime(timestamp.split("+")[0], "%Y-%m-%dT%H:%M:%S.%f")
        return dt.strftime("%Y-%m-%d %H:%M:%S")  # Convert to readable format
    except ValueError:
        return "Invalid Date"

# Function to extract and write waiver details to CSV
def write_waivers_to_csv(data):
    with open(OUTPUT_CSV, mode='w', newline='') as file:
        writer = csv.writer(file)
        # Write header
        writer.writerow([
            'Repository Public ID', 'Component Format', 'Component Artifact ID', 'Component Group ID',
            'Component Version', 'Create Time', 'Expiry Time', 'Reason Text',
            'Policy Name', 'Threat Level'
        ])

        # Iterate over repository waivers
        repository_waivers = data.get('repositoryWaivers', None)
        if repository_waivers is None:
            print("No 'repositoryWaivers' key found in response!")
        elif not repository_waivers:
            print("No repository waivers found.")
        else:
            for waiver in data.get('repositoryWaivers', []):
                repository = waiver.get("repository", {})
                repository_name = repository.get("publicId", "N/A")

                for stage in waiver.get("stages", []):
                    for violation in stage.get("componentPolicyViolations", []):
                        component = violation.get("component", {})
                        identifier = component.get("componentIdentifier", {})
                        coordinates = identifier.get("coordinates", {})

                        artifact_id = coordinates.get("artifactId", "N/A")
                        group_id = coordinates.get("groupId", "N/A")
                        version = coordinates.get("version", "N/A")
                        component_format = identifier.get("format", "N/A")

                        for waived_violation in violation.get("waivedPolicyViolations", []):
                            policy_name = str(waived_violation.get("policyName", "N/A"))
                            threat_level = waived_violation.get("threatLevel", 0)
                            if isinstance(threat_level, str):
                                #print(f"⚠️ Warning: threatLevel is a string: {threat_level}")  # Debugging
                                threat_level = int(threat_level)  # Convert to int safely
                            reason_text = str(waived_violation.get("policyWaiver", {}).get("reasonText", "N/A"))
                            policy_waiver = waived_violation.get("policyWaiver", {})  # Avoids None errors
                            create_time = policy_waiver.get("createTime", "N/A")
                            expiry_time = policy_waiver.get("expiryTime", "N/A")

                            #print(f"Raw create_time: {create_time}, expiry_time: {expiry_time}")  # Debugging

                            writer.writerow([
                                repository_name, str(component_format), str(artifact_id), str(group_id), str(version),
                                str(format_timestamp(create_time)), str(format_timestamp(expiry_time)),
                                str(reason_text), str(policy_name), str(threat_level)
                            ])

if __name__ == '__main__':
    try:
        waivers_data = fetch_waivers()
        write_waivers_to_csv(waivers_data)
        print(f'Waiver details have been written to {OUTPUT_CSV}')
    except Exception as e:
        print(f'An error occurred: {e}')
