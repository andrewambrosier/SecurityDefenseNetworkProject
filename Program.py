from log import Log
from log_analyzer import LogAnalyzer

def main():
    # Create Log objects
    logs = [
        Log("2024-12-01 10:00:00", "failed_login", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:01:00", "failed_login", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:02:00", "failed_login", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:03:00", "failed_login", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:04:00", "failed_login", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:05:00", "normal", "192.168.1.3", "192.168.1.1"),
        Log("2024-12-01 10:06:00", "normal", "192.168.1.4", "192.168.1.1"),
    ]
    
    # Create LogAnalyzer and pass the logs
    analyzer = LogAnalyzer(logs)
    
    # Detect attacks
    attacks = analyzer.detect_brute_force()
    print(f"Brute force detected from IPs: {attacks}")
    

if __name__ == "__main__":
    main()

