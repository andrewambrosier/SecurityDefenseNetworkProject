from collections import defaultdict
import time

class LogAnalyzer:
    # This class will handle the detection of the attacks in the list of log objects. It will have methods to analyze logs and detect specific attack patterns.
    def __init__(self, logs):
        self.logs = logs
        self.attack_threshold = 5
        self.time_window = 60  # Define the time window for DoS detection (in seconds)
        self.request_threshold = 10

    def detect_brute_force(self):
        # Detect brute force attacks by counting the number of failed login attempts from the same IP address.
        failed_attempts = defaultdict(int)
    
        # Loop through the list of log objects and count the number of failed login attempts
        for log in self.logs:
            if log.event_type == "failed_login":
                failed_attempts[log.source_ip] += 1 

        # Return the IP addresses of the brute force attacks with the specified threshold
        brute_force_ips = [ip for ip, count in failed_attempts.items() if count >= self.attack_threshold]
        return brute_force_ips
    
    def detect_dos_attacks(self):
        # Detect DoS (Denial of Service) attacks by counting the number of requests from the same IP address within a specific time frame.
        request_count = defaultdict(list)
        sus_ips = []
    
        # Loop through to get the timestamps for each IP
        for log in self.logs:
            request_count[log.source_ip].append(log.timestamp)

        # Check for IP request time
        for ip, timestamps in request_count.items():
            timestamps.sort()

            for i in range(len(timestamps)): # Check for more threshold reqs in time window
                count = 0
                for j in range(i, len(timestamps)): # Count reqs within time window
                    if (timestamps[j] - timestamps[i]).total_seconds() <= self.time_window:
                        count += 1
                    else:
                        break
                
                # If the count exceeds the threshold, add the IP to suspicious IPs list
                if count >= self.request_threshold:
                    sus_ips.append(ip)
                    break

        return sus_ips