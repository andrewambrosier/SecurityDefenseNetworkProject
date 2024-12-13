from collections import defaultdict

class LogAnalyzer:
    # This class will handle the detection of the attacks in the list of log objects. It will have methods to analyze logs and detect specific attack patterns.
    def __init__(self, logs):
        self.logs = logs

    def detect_brute_force(self):
        # Detect brute force attacks by counting the number of failed login attempts from the same IP address.
        failed_attempts = defaultdict(int)
        attack_threshold = 5

        # Loop through the list of log objects and count the number of failed login attempts
        for log in self.logs:
            if log.event_type == "failed_login":
                failed_attempts[log.source_ip] += 1 #increment the failed attempts for the source IP

        # Return the IP addresses of the brute force attacks with the specified threshold
        brute_force_ips = [ip for ip, count in failed_attempts.items() if count >= attack_threshold]
        return brute_force_ips