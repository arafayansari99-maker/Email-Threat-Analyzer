#!/usr/bin/env python
"""Test login."""
import requests

url = "http://localhost:8000/api/auth/login"
data = {"username": "admin", "password": "admin123"}
headers = {"Content-Type": "application/x-www-form-urlencoded"}

try:
    resp = requests.post(url, data=data, headers=headers, timeout=10)
    print(f"Status: {resp.status_code}")
    print(f"Response: {resp.text[:500]}")
except Exception as e:
    print(f"Error: {e}")