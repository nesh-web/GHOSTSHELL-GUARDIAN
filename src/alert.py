# src/alert.py
"""
Alert data structures and utilities for SOC alerts.
"""

class Alert:
    def __init__(self, source_ip: str, payload: str, user_agent: str):
        self.source_ip = source_ip
        self.payload = payload
        self.user_agent = user_agent

    def to_dict(self):
        return {
            "source_ip": self.source_ip,
            "payload": self.payload,
            "user_agent": self.user_agent
        }

    def __repr__(self):
        return f"Alert(ip={self.source_ip}, payload={self.payload[:30]}...)"
