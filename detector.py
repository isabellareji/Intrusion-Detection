from collections import defaultdict, deque
from datetime import datetime

LOG_FILE = "logs/network_logs.txt"
ALERT_FILE = "alerts.txt"

PORT_SCAN_THRESHOLD = 5
BRUTE_FORCE_THRESHOLD = 4
TIME_WINDOW_SECONDS = 20


def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert = f"{timestamp} {message}"

    with open(ALERT_FILE, "a") as file:
        file.write(alert + "\n")

    print(alert)


def parse_time(date_str, time_str):
    return datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")


def detect_attacks():
    port_activity = defaultdict(lambda: deque())
    login_failures = defaultdict(lambda: deque())

    with open(LOG_FILE, "r") as file:
        for line in file:
            if not line.strip():
                continue

            parts = line.split()
            timestamp = parse_time(parts[0], parts[1])
            ip = parts[2]
            event = parts[3]

            if event == "PORT":
                port = parts[4]
                port_activity[ip].append((timestamp, port))

            elif event == "LOGIN_FAIL":
                login_failures[ip].append(timestamp)

    # Detect port scans
    for ip, events in port_activity.items():
        ports = set()
        times = deque()

        for timestamp, port in events:
            times.append(timestamp)
            ports.add(port)

            while (times[-1] - times[0]).seconds > TIME_WINDOW_SECONDS:
                times.popleft()

        if len(ports) >= PORT_SCAN_THRESHOLD:
            log_alert(
                f"[ALERT] Port scan detected from {ip} ({len(ports)} ports in {TIME_WINDOW_SECONDS}s)"
            )

    # Detect brute force attempts
    for ip, times in login_failures.items():
        while len(times) >= BRUTE_FORCE_THRESHOLD:
            if (times[-1] - times[0]).seconds <= TIME_WINDOW_SECONDS:
                log_alert(
                    f"[ALERT] Brute force login attempt from {ip} ({len(times)} failures in {TIME_WINDOW_SECONDS}s)"
                )
                break
            times.popleft()


if __name__ == "__main__":
    detect_attacks()
