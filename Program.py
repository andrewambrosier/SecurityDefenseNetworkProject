from log import Log
from log_analyzer import LogAnalyzer, SeverityAssessor, ResponseDecider, AlertSystem

def main():
    # Create Log objects
    logs = [
        Log("2024-12-01 10:00:00", "normal", "192.168.1.1", "192.168.1.1"),
        Log("2024-12-01 10:00:01", "normal", "192.168.1.1", "192.168.1.1"),
        Log("2024-12-01 10:00:02", "normal", "192.168.1.1", "192.168.1.1"),
        Log("2024-12-01 10:00:03", "normal", "192.168.1.1", "192.168.1.1"),
        Log("2024-12-01 10:00:04", "normal", "192.168.1.1", "192.168.1.1"),
        # Simulating DoS Attacks from the same IP
        Log("2024-12-01 10:00:00", "normal", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:00:01", "normal", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:00:02", "normal", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:00:03", "normal", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:00:04", "normal", "192.168.1.2", "192.168.1.1"),
        # Simulating failed login attempts from the same IP (brute-force attack)
        Log("2024-12-01 10:00:05", "failed_login", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:00:06", "failed_login", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:00:07", "failed_login", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:00:08", "failed_login", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:00:09", "failed_login", "192.168.1.2", "192.168.1.1"),
        # Adding more failed login attempts to exceed the attack threshold
        Log("2024-12-01 10:00:10", "failed_login", "192.168.1.3", "192.168.1.1"),
        Log("2024-12-01 10:00:11", "failed_login", "192.168.1.3", "192.168.1.1"),
        Log("2024-12-01 10:00:12", "failed_login", "192.168.1.3", "192.168.1.1"),
        Log("2024-12-01 10:00:13", "failed_login", "192.168.1.3", "192.168.1.1"),
        Log("2024-12-01 10:00:14", "failed_login", "192.168.1.3", "192.168.1.1"),
        # Adding more failed login attempts to exceed the high threat threshold
        Log("2024-12-01 10:00:10", "failed_login", "192.168.1.4", "192.168.1.1"),
        Log("2024-12-01 10:00:11", "failed_login", "192.168.1.4", "192.168.1.1"),
        Log("2024-12-01 10:00:12", "failed_login", "192.168.1.4", "192.168.1.1"),
        Log("2024-12-01 10:00:13", "failed_login", "192.168.1.4", "192.168.1.1"),
        Log("2024-12-01 10:00:14", "failed_login", "192.168.1.4", "192.168.1.1"),
        Log("2024-12-01 10:00:10", "failed_login", "192.168.1.5", "192.168.1.1"),
        Log("2024-12-01 10:00:11", "failed_login", "192.168.1.5", "192.168.1.1"),
        Log("2024-12-01 10:00:12", "failed_login", "192.168.1.5", "192.168.1.1"),
        Log("2024-12-01 10:00:13", "failed_login", "192.168.1.5", "192.168.1.1"),
        Log("2024-12-01 10:00:14", "failed_login", "192.168.1.5", "192.168.1.1")
    ]

    
    # Create LogAnalyzer and pass the logs
    analyzer = LogAnalyzer(logs)
    
    # Detect attacks
    brute_attacks = analyzer.detect_brute_force()
    print(f"Brute force detected from IPs: {brute_attacks}")

    dos_ips = analyzer.detect_dos_attacks()
    print(f"Potential DoS from IPs: {dos_ips}")
    
    # Assess severity of attacks
    assessor = SeverityAssessor()
    severity = assessor.assess_severity(brute_attacks, dos_ips)
    print(f"Severity assessment: {severity}")

    # Recommend actions based on severity
    decider = ResponseDecider()
    actions = decider.recommend_actions(severity)
    print(f"Recommended actions: {actions}")

    # Send alerts
    alert_system = AlertSystem()
    alert_system.send_alert(actions)

if __name__ == "__main__":
    main()

