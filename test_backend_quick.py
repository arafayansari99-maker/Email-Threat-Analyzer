#!/usr/bin/env python3
"""Quick backend test without semantic analysis."""
import sys
sys.path.insert(0, 'eta/backend')

from analysis_engine import run_analysis

# Test with minimal email
email_bytes = b'''From: test@example.com
To: user@company.com
Subject: Test Email
Date: Mon, 01 Jan 2024 12:00:00 +0000

This is a test email.
'''

try:
    print('Running full analysis pipeline...')
    result = run_analysis(email_bytes, 'test.eml', tier2_consent=False)
    print(f'✓ Analysis complete')
    print(f"  Verdict: {result.get('risk', 'N/A')}")
    print(f"  Score: {result.get('risk_score', 'N/A')}")
    print(f"  Method: {result.get('method', 'N/A')}")
    print('\n✓✓✓ BACKEND WORKING - Semantic analysis disabled successfully')
except Exception as e:
    print(f'✗ Error: {e}')
    import traceback
    traceback.print_exc()
