from log import Log
from log_analyzer import LogAnalyzer

def main():
    # Create Log objects
    logs = [
        Log("2024-12-01 10:00:00", "normal", "192.168.1.2", "192.168.1.1"),
        Log("2024-12-01 10:05:00", "brute_force", "192.168.1.5", "192.168.1.10"),
        Log("2024-12-01 10:10:00", "malware", "192.168.1.8", "192.168.1.20")
    ]
    
    # Create LogAnalyzer and pass the logs
    analyzer = LogAnalyzer(logs)
    
    # Detect attacks
    attacks = analyzer.detect_attacks()
    
    # Print detected attacks
    for attack in attacks:
        print(f"Detected Attack: {attack.event_type} at {attack.timestamp} from {attack.source_ip}")

if __name__ == "__main__":
    main()

