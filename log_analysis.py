import re
import csv
import pandas as pd
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"

# Function to parse each log line and extract data based on regex
def parse_log(log_lines):
    data = []
    log_pattern = (
        r'^(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>[A-Z]+) (?P<endpoint>\S+) HTTP/[0-9.]+" (?P<status>\d+) (?P<size>\d+)(?: ".*")?$'
    )
    for line in log_lines:
        match = re.match(log_pattern, line)  # Apply regex pattern to each log line
        if match:
            data.append(match.groupdict())  # Append the matched groups to data
    return data

# Function to count the number of requests made from each IP address
def count_requests_per_ip(log_lines):
    ip_count = defaultdict(int)  # Dictionary to store IP addresses and their request count
    for line in log_lines:
        match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)  # Find the IP address in the log line
        if match:
            ip_count[match.group(1)] += 1  # Increment the count for the matched IP address
    return sorted(ip_count.items(), key=lambda x: x[1], reverse=True)  # Sort IPs by request count

# Function to find the most frequently accessed endpoint
def most_frequently_accessed_endpoint(log_lines):
    endpoint_count = defaultdict(int)  # Dictionary to store endpoints and their access count
    for line in log_lines:
        match = re.search(r'"[A-Z]+ (\S+) HTTP/', line)  # Find the endpoint in the log line
        if match:
            endpoint_count[match.group(1)] += 1  # Increment the count for the matched endpoint
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1])  # Find the most accessed endpoint
    return most_accessed

# Function to detect suspicious activity based on failed login attempts (e.g., 401 errors or invalid credentials)
def detect_suspicious_activity(log_lines):
    failed_logins = defaultdict(int)  # Dictionary to store IPs and failed login counts
    for line in log_lines:
        if '401' in line or 'Invalid credentials' in line:  # Check for failed login attempts
            match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)  # Find the IP address in the failed login line
            if match:
                failed_logins[match.group(1)] += 1  # Increment the failed login count for the IP
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}  # Filter IPs with failed logins exceeding the threshold
    return suspicious_ips

# Function to save the analysis results to a CSV file
def save_to_csv(requests_per_ip, most_accessed, suspicious_ips):
    with open(OUTPUT_CSV, mode='w', newline='') as file:
        writer = csv.writer(file)

        writer.writerow(["IP Address", "Request Count"])  # Write headers for IP requests
        writer.writerows(requests_per_ip)  # Write IP request data

        writer.writerow([])  # Add a blank line for separation
        writer.writerow(["Endpoint", "Access Count"])  # Write headers for endpoints
        writer.writerow(most_accessed)  # Write most accessed endpoint data

        writer.writerow([])  # Add a blank line for separation
        writer.writerow(["IP Address", "Failed Login Count"])  # Write headers for failed logins
        writer.writerows(suspicious_ips.items())  # Write suspicious IPs data

# Main function to read the log file, perform analysis, and output results
def main():
    with open(LOG_FILE, 'r') as file:
        log_lines = file.readlines()  # Read all lines from the log file

    parsed_data = parse_log(log_lines)  # Parse the log data using the regex
    if not parsed_data:
        print("No data parsed from the log file. Check the log format.")
        return  # If no data is parsed, stop the execution

    df = pd.DataFrame(parsed_data)  # Convert the parsed data into a DataFrame for analysis
    df['status'] = df['status'].astype(int)  # Convert 'status' column to integer
    df['size'] = df['size'].astype(int)  # Convert 'size' column to integer

    print("DataFrame Head:")  # Print the first few rows of the DataFrame
    print(df.head())

    print("\nDataFrame Info:")  # Print summary info about the DataFrame
    print(df.info())

    # Perform further log analysis
    requests_per_ip = count_requests_per_ip(log_lines)  # Count requests per IP
    most_accessed = most_frequently_accessed_endpoint(log_lines)  # Find most accessed endpoint
    suspicious_ips = detect_suspicious_activity(log_lines)  # Detect suspicious activity (failed logins)

    # Print the results to the console
    print("\nRequests per IP:")
    for ip, count in requests_per_ip:
        print(f"{ip}: {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} accessed {most_accessed[1]} times")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip}: {count} failed login attempts")

    # Save the results to a CSV file
    save_to_csv(requests_per_ip, most_accessed, suspicious_ips)

# Run the main function when the script is executed
if __name__ == "__main__":
    main()
