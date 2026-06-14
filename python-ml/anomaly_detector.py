"""
Anomaly Detector - Real-time network traffic anomaly detection
Uses statistical analysis to flag unusual traffic patterns
Author: Devesh Alukuri
"""

import json
import math
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict


class AnomalyDetector:

    def __init__(self):
        self.ip_request_counts = defaultdict(list)
        self.ip_port_counts = defaultdict(set)
        self.thresholds = {
            "requests_per_minute": 100,
            "unique_ports_per_ip": 15,
            "payload_entropy_threshold": 6.5,
            "packet_size_zscore": 3.0
        }

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        freq = defaultdict(int)
        for char in data:
            freq[char] += 1
        entropy = 0.0
        for count in freq.values():
            prob = count / len(data)
            if prob > 0:
                entropy -= prob * math.log2(prob)
        return round(entropy, 4)

    def detect_port_scan(self, source_ip: str, dest_port: int) -> Dict:
        """Detect if an IP is scanning multiple ports."""
        self.ip_port_counts[source_ip].add(dest_port)
        unique_ports = len(self.ip_port_counts[source_ip])

        if unique_ports >= self.thresholds["unique_ports_per_ip"]:
            return {
                "anomaly_detected": True,
                "type": "PORT_SCAN",
                "detail": f"IP {source_ip} has scanned {unique_ports} unique ports",
                "severity": "HIGH"
            }
        return {"anomaly_detected": False}

    def detect_ddos(self, source_ip: str, timestamp: datetime = None) -> Dict:
        """Detect DDoS by counting requests per minute from an IP."""
        if timestamp is None:
            timestamp = datetime.now()

        self.ip_request_counts[source_ip].append(timestamp)

        # Keep only last 60 seconds
        cutoff = timestamp - timedelta(seconds=60)
        self.ip_request_counts[source_ip] = [
            t for t in self.ip_request_counts[source_ip] if t > cutoff
        ]

        request_rate = len(self.ip_request_counts[source_ip])
        if request_rate >= self.thresholds["requests_per_minute"]:
            return {
                "anomaly_detected": True,
                "type": "DDOS",
                "detail": f"IP {source_ip} sent {request_rate} requests in last 60 seconds",
                "severity": "CRITICAL"
            }
        return {"anomaly_detected": False}

    def detect_payload_anomaly(self, payload: str) -> Dict:
        """Detect anomalies in payload content using entropy analysis."""
        if not payload:
            return {"anomaly_detected": False}

        entropy = self.calculate_entropy(payload)
        payload_lower = payload.lower()

        # SQL injection patterns
        sql_patterns = ["select ", "union ", "drop table", "insert into", "' or '1'='1", "--"]
        if any(p in payload_lower for p in sql_patterns):
            return {
                "anomaly_detected": True,
                "type": "SQL_INJECTION",
                "detail": "SQL injection pattern detected in payload",
                "entropy": entropy,
                "severity": "HIGH"
            }

        # XSS patterns
        xss_patterns = ["<script>", "javascript:", "onerror=", "onload=", "alert("]
        if any(p in payload_lower for p in xss_patterns):
            return {
                "anomaly_detected": True,
                "type": "XSS",
                "detail": "Cross-site scripting pattern detected",
                "entropy": entropy,
                "severity": "HIGH"
            }

        # High entropy may indicate encrypted malware traffic
        if entropy > self.thresholds["payload_entropy_threshold"]:
            return {
                "anomaly_detected": True,
                "type": "MALWARE_TRAFFIC",
                "detail": f"Suspiciously high payload entropy: {entropy}",
                "entropy": entropy,
                "severity": "MEDIUM"
            }

        return {"anomaly_detected": False, "entropy": entropy}

    def analyze_event(self, event: Dict) -> Dict:
        """Full analysis of a single network event."""
        results = []

        # Check port scan
        if "source_ip" in event and "dest_port" in event:
            scan_result = self.detect_port_scan(event["source_ip"], event["dest_port"])
            if scan_result["anomaly_detected"]:
                results.append(scan_result)

        # Check DDoS
        if "source_ip" in event:
            ddos_result = self.detect_ddos(event["source_ip"])
            if ddos_result["anomaly_detected"]:
                results.append(ddos_result)

        # Check payload
        if "payload" in event:
            payload_result = self.detect_payload_anomaly(event["payload"])
            if payload_result["anomaly_detected"]:
                results.append(payload_result)

        return {
            "source_ip": event.get("source_ip"),
            "anomalies_detected": len(results),
            "anomalies": results,
            "analyzed_at": datetime.now().isoformat()
        }


if __name__ == "__main__":
    detector = AnomalyDetector()

    # Sample test events
    test_events = [
        {"source_ip": "192.168.1.100", "dest_port": 22, "payload": ""},
        {"source_ip": "192.168.1.100", "dest_port": 3389, "payload": ""},
        {"source_ip": "10.0.0.5", "dest_port": 80, "payload": "SELECT * FROM users WHERE id='1' OR '1'='1'"},
        {"source_ip": "172.16.0.1", "dest_port": 443, "payload": "<script>alert('XSS')</script>"},
    ]

    print("=== Anomaly Detection Results ===\n")
    for event in test_events:
        result = detector.analyze_event(event)
        print(json.dumps(result, indent=2))
        print("-" * 40)
