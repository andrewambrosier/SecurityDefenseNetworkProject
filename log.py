class Log:
    # This class implements the the log entries. Stores details like timestamp, event_type, source_ip, and destination_ip.
    # This should let us manage the data better.
    def __init__(self, timestamp, event_type, source_ip, destination_ip):
        self.timestamp = timestamp
        self.event_type = event_type
        self.source_ip = source_ip
        self.destination_ip = destination_ip

    def __str__(self):
        return f"Log({self.timestamp}, {self.event_type}, {self.source_ip}, {self.destination_ip})"