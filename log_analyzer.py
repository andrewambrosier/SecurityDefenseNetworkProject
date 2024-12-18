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
    
    
class SeverityAssessor:
    # This class assigns severity levels (low, medium, high) to detected attacks based on the number of affected IPs
    def assess_severity(self, brute_force_ips, dos_ips):
        severity = {}

        # Determine severity level for brute force attacks
        if len(brute_force_ips) > 3:
            severity["BruteForce"] = "high"
        elif len(brute_force_ips) > 1:
            severity["BruteForce"] = "medium"
        elif brute_force_ips:  # At least one IP
            severity["BruteForce"] = "low"

        # Determine severity level for DoS attacks
        if len(dos_ips) > 3:
            severity["DoS"] = "high"
        elif len(dos_ips) > 1:
            severity["DoS"] = "medium"
        elif dos_ips:  # At least one IP
            severity["DoS"] = "low"

        return severity

    

class ResponseDecider:
    # This class recommends actions based on the severity of the detected attacks
    def recommend_actions(self, severity_assessment):
        actions = {}
        #Method that cycles through attack types and their severity and reccomends actions based on that info
        for attack_type, severity in severity_assessment.items():
            if severity == "high":
                actions[attack_type] = "Isolate System"
            elif severity == "medium":
                actions[attack_type] = "Investigate Logs"
            else:
                actions[attack_type] = "Monitor Activity"
        
        # Return recommended actions for each attack type
        return actions
    

class AlertSystem:
    # This class sends alerts notifing operator about the detected attacks and the determined suggested actions
    def send_alert(self, actions):
        for attack_type, action in actions.items():
            print(f"ALERT: {attack_type} detected. Recommended action: {action}")
