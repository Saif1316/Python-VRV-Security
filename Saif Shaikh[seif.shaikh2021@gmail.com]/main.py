import csv
import re
from collections import Counter


def parse_log_line(line):
    """Parse a single log entry."""
    pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>.+?)\] "(?P<method>[A-Z]+) (?P<url>.+?) HTTP/[\d\.]+"' \
              r' (?P<status>\d+) (?P<size>\d+)( "(?P<message>.+?)")?'
    match = re.match(pattern, line)
    return match.groupdict() if match else None


def count_requests_per_ip(file_path):
    ip_counts = Counter()
    with open('sample.log', 'r') as file:
        for line in file:
            parsed = parse_log_line(line)
            if parsed:
                ip_counts[parsed['ip']] += 1
    return ip_counts


def detect_most_accessed_endpoint(file_path):
    url_count = Counter()
    with open('sample.log', 'r') as file:
        for line in file:
            parsed = parse_log_line(line)
            if parsed:
                url_count[parsed['url']] += 1
    most_accessed = url_count.most_common(1)
    return most_accessed[0]


def detect_suspicious_activity(file_path, threshold=10):
    failed_attempts = Counter()
    with open('sample.log', 'r') as file:
        for line in file:
            parsed = parse_log_line(line)
            if parsed and (parsed['status'] == 401 or parsed.get('message') == "Invalid Credentials"):
                failed_attempts[parsed['ip']] += 1
    suspicious_activity = {ip:count for ip,count in failed_attempts.items() if count > threshold}
    return suspicious_activity


def save_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_activity, filename='log_analysis_result.csv'):
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)

        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in requests_per_ip.items():
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(['Most Frequently Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip,count in suspicious_activity.items():
            writer.writerow([ip, count])


def display_result(requests_per_ip, most_accessed_endpoint, suspicious_activity):
    print(f"{'IP Address':<20} {'Request Count':<15}")
    print('-' * 35)
    for ip, count in requests_per_ip.items():
        print(f"{ip:<20} {count:<15}")
    print("\n")

    print("Most Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed{most_accessed_endpoint[1]})")
    print("\n")

    print("Suspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
    print('-' * 40)
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count:<20}")


def analyze_log(filepath):
    request_per_ip = count_requests_per_ip(filepath)

    most_accessed_endpoint = detect_most_accessed_endpoint(filepath)

    suspicious_activity = detect_suspicious_activity(filepath)

    display_result(request_per_ip, most_accessed_endpoint, suspicious_activity)

    save_to_csv(request_per_ip, most_accessed_endpoint, suspicious_activity)


file_path = "sample.log"
analyze_log(file_path)





