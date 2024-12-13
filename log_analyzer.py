class LogAnalyzer:
    # This class will handle the detection of the attacks in the list of log objects. It will have methods to analyze logs and detect specific attack patterns.
    def __init__(self, logs):
        self.logs = logs

    def detect_attacks(self):
        attack_patterns = ["brute_force", "malware"]
        detected_attacks = []

        for log in self.logs:
            if log.event_type in attack_patterns:
                detected_attacks.append(log)

        return detected_attacks