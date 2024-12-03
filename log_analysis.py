import re
import csv
from typing import Dict, List, Tuple
import pandas as pd

class LogAnalyzer:
    def __init__(self, log_file: str, failed_login_threshold: int = 10):
        self.log_file = log_file
        self.failed_login_threshold = failed_login_threshold
        self.ip_requests: Counter = Counter()
        self.endpoint_requests: Counter = Counter()
        self.failed_logins: Counter = Counter()

    def parse_log_file(self) -> None:
        """Parse the log file and collect statistics."""
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        endpoint_pattern = r'"[A-Z]+ ([^"]+)'
        
        with open(self.log_file, 'r') as f:
            for line in f:
                # Extract IP address
                ip_match = re.search(ip_pattern, line)
                if ip_match:
                    ip = ip_match.group(1)
                    self.ip_requests[ip] += 1

                # Extract endpoint
                endpoint_match = re.search(endpoint_pattern, line)
                if endpoint_match:
                    endpoint = endpoint_match.group(1).split()[0]  # Get path without HTTP version
                    self.endpoint_requests[endpoint] += 1

                # Check for failed login attempts (HTTP 401)
                if 'POST /login' in line and '401' in line:
                    self.failed_logins[ip] += 1

    def get_requests_per_ip(self) -> List[Tuple[str, int]]:
        """Return sorted list of (IP, request_count) tuples."""
        return sorted(self.ip_requests.items(), key=lambda x: x[1], reverse=True)

    def get_most_accessed_endpoint(self) -> Tuple[str, int]:
        """Return the most frequently accessed endpoint and its count."""
        return self.endpoint_requests.most_common(1)[0]

    def get_suspicious_activity(self) -> List[Tuple[str, int]]:
        """Return IPs with failed login attempts exceeding the threshold."""
        return [(ip, count) for ip, count in self.failed_logins.items() 
                if count >= self.failed_login_threshold]

    def save_results_to_csv(self, output_file: str) -> None:
        """Save analysis results to a CSV file."""
        # Create DataFrames for each section
        requests_df = pd.DataFrame(self.get_requests_per_ip(), 
                                 columns=['IP Address', 'Request Count'])
        endpoint_df = pd.DataFrame([self.get_most_accessed_endpoint()], 
                                 columns=['Endpoint', 'Access Count'])
        suspicious_df = pd.DataFrame(self.get_suspicious_activity(), 
                                   columns=['IP Address', 'Failed Login Count'])

        # Save to CSV with sections
        with open(output_file, 'w', newline='') as f:
            f.write("Requests per IP\n")
            requests_df.to_csv(f, index=False)
            f.write("\nMost Accessed Endpoint\n")
            endpoint_df.to_csv(f, index=False)
            f.write("\nSuspicious Activity\n")
            suspicious_df.to_csv(f, index=False)

    def display_results(self) -> None:
        """Display analysis results in the terminal."""
        print("IP Address           Request Count")
        print("-" * 40)
        for ip, count in self.get_requests_per_ip():
            print(f"{ip:<18} {count:>10}")

        print("\nMost Frequently Accessed Endpoint:")
        endpoint, count = self.get_most_accessed_endpoint()
        print(f"{endpoint} (Accessed {count} times)")

        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        print("-" * 40)
        for ip, count in self.get_suspicious_activity():
            print(f"{ip:<18} {count:>10}")

def main():
    # Initialize and run analysis
    analyzer = LogAnalyzer('sample.log', failed_login_threshold=3)
    analyzer.parse_log_file()
    
    # Display results in terminal
    analyzer.display_results()
    
    # Save results to CSV
    analyzer.save_results_to_csv('log_analysis_results.csv')

if __name__ == "__main__":
    main()
