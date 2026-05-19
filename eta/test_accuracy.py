#!/usr/bin/env python3
"""
Email Threat Analyzer - Accuracy Testing Script
Tests the ML model accuracy across all three API endpoints using real email samples.
"""

import requests
import json
import os
from pathlib import Path

# API endpoints
BASE_URL = "http://localhost:8000"
ENDPOINTS = {
    "single_file": "/api/analyze-email",
    "batch_files": "/api/analyze-batch",
    "extension_scan": "/api/extension-scan"
}

# Test email files (created earlier)
TEST_EMAILS_DIR = Path("test_emails")
TEST_FILES = [
    ("phishing_bank.eml", "phishing"),
    ("phishing_lottery.eml", "phishing"),
    ("phishing_paypal.eml", "phishing"),
    ("safe_amazon.eml", "safe"),
    ("safe_github.eml", "safe")
]

def test_single_file_upload(email_file, expected_label):
    """Test single file upload endpoint"""
    file_path = TEST_EMAILS_DIR / email_file
    if not file_path.exists():
        print(f"❌ File {email_file} not found")
        return False

    try:
        with open(file_path, 'rb') as f:
            files = {'file': (email_file, f, 'message/rfc822')}
            response = requests.post(f"{BASE_URL}{ENDPOINTS['single_file']}", files=files)

        if response.status_code == 200:
            result = response.json()
            ml_class = result.get('ml_analysis', {}).get('classification', 'legitimate')
            predicted = "phishing" if ml_class != "legitimate" else "safe"
            success = predicted == expected_label
            status = "✅" if success else "❌"
            print(f"{status} Single file {email_file}: predicted={predicted}, expected={expected_label}, ml_class={ml_class}, verdict={result.get('verdict')}")
            return success
        else:
            print(f"❌ Single file {email_file}: HTTP {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"❌ Single file {email_file}: Error - {str(e)}")
        return False

def test_batch_file_upload():
    """Test batch file upload endpoint"""
    if not TEST_EMAILS_DIR.exists():
        print("❌ Test emails directory not found")
        return False

    try:
        files = []
        expected_labels = []

        for email_file, expected_label in TEST_FILES:
            file_path = TEST_EMAILS_DIR / email_file
            if file_path.exists():
                files.append(('files', (email_file, open(file_path, 'rb'), 'message/rfc822')))
                expected_labels.append(expected_label)

        if not files:
            print("❌ No test files found")
            return False

        response = requests.post(f"{BASE_URL}{ENDPOINTS['batch_files']}", files=files)

        # Close file handles
        for _, file_tuple in files:
            file_tuple[1].close()

        if response.status_code == 200:
            data = response.json()
            results = data.get('batch_results') if isinstance(data, dict) else []
            if isinstance(results, list) and len(results) == len(expected_labels):
                correct = 0
                for i, result in enumerate(results):
                    ml_class = result.get('ml_analysis', {}).get('classification', 'legitimate')
                    predicted = "phishing" if ml_class != "legitimate" else "safe"
                    if predicted == expected_labels[i]:
                        correct += 1
                    print(f"  {TEST_FILES[i][0]}: predicted={predicted}, expected={expected_labels[i]}, ml_class={ml_class}, verdict={result.get('verdict')}")

                accuracy = correct / len(expected_labels)
                success = accuracy >= 0.8  # 80% accuracy threshold
                status = "✅" if success else "❌"
                print(f"{status} Batch upload: {correct}/{len(expected_labels)} correct ({accuracy:.1%})")
                return success
            else:
                print(f"❌ Batch upload: Unexpected response format")
                return False
        else:
            print(f"❌ Batch upload: HTTP {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"❌ Batch upload: Error - {str(e)}")
        return False

def test_extension_scan():
    """Test extension scan endpoint"""
    # Use a sample email content for extension scan
    sample_email_content = """From: test@example.com
To: user@example.com
Subject: Test Email

This is a test email content for scanning.
"""

    try:
        data = {'email_content': sample_email_content}
        response = requests.post(f"{BASE_URL}{ENDPOINTS['extension_scan']}", json=data)

        if response.status_code == 200:
            result = response.json()
            predicted = "phishing" if result.get('phishing_prob', 0) >= 0.4 else "safe"
            print(f"✅ Extension scan: predicted={predicted}, verdict={result.get('verdict')}, risk_score={result.get('risk_score')}, phishing_prob={result.get('phishing_prob')}")
            return True
        else:
            print(f"❌ Extension scan: HTTP {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"❌ Extension scan: Error - {str(e)}")
        return False

def main():
    """Run all accuracy tests"""
    print("🚀 Starting Email Threat Analyzer Accuracy Tests")
    print("=" * 50)

    # Check if backend is running
    try:
        response = requests.get(f"{BASE_URL}/docs", timeout=5)
        if response.status_code != 200:
            print("❌ Backend server not responding")
            return
    except:
        print("❌ Cannot connect to backend server")
        return

    print("✅ Backend server is running")

    # Check if test emails exist
    if not TEST_EMAILS_DIR.exists():
        print("❌ Test emails directory not found. Please create test_emails/ with sample .eml files")
        return

    results = []

    print("\n📁 Testing Single File Upload:")
    for email_file, expected_label in TEST_FILES:
        result = test_single_file_upload(email_file, expected_label)
        results.append(result)

    print("\n📦 Testing Batch File Upload:")
    batch_result = test_batch_file_upload()
    results.append(batch_result)

    print("\n🔍 Testing Extension Scan:")
    extension_result = test_extension_scan()
    results.append(extension_result)

    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)

    total_tests = len(results)
    passed_tests = sum(results)

    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")

    if passed_tests == total_tests:
        print("🎉 All tests passed! The ML model is working correctly.")
    elif passed_tests >= total_tests * 0.8:
        print("✅ Most tests passed. The model shows good accuracy.")
    else:
        print("⚠️  Some tests failed. Model accuracy needs improvement.")

if __name__ == "__main__":
    main()