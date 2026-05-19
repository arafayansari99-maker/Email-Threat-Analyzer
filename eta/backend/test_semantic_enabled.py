#!/usr/bin/env python3
"""Test that semantic analysis is enabled in the pipeline."""
import os
import sys
import json
from pathlib import Path

sys.path.insert(0, os.getcwd())

from analysis_engine import run_analysis

# Find a sample phishing email
sample_files = [
    Path("../../test_emails/bank_phishing.eml"),
    Path("../../test_emails/phishing_bank.eml"),
    Path("test_emails/bank_phishing.eml"),
    Path("test_emails/phishing_bank.eml"),
]

sample_path = None
for p in sample_files:
    if p.exists():
        sample_path = p
        break

if not sample_path:
    print("ERROR: No sample phishing emails found")
    sys.exit(1)

print(f"Testing with: {sample_path}")
print("=" * 60)

with open(sample_path, "rb") as f:
    result = run_analysis(f.read(), sample_path.name, tier2_consent=False)

print(f"\n✓ Verdict: {result['verdict']}")
print(f"✓ Risk Score: {result['risk_score']}")

print(f"\nSemantic Analysis:")
print(json.dumps(result["semantic_analysis"], indent=2))

print(f"\nRisk Breakdown:")
for key, value in result["breakdown"].items():
    if value is not None:
        print(f"  {key}: {value}")

if result["semantic_analysis"].get("method") == "unavailable":
    print("\n❌ ERROR: Semantic model is UNAVAILABLE")
    sys.exit(1)
elif result["semantic_analysis"].get("semantic_prob", 0) > 0:
    print(f"\n✓ SUCCESS: Semantic analysis is ENABLED (prob={result['semantic_analysis']['semantic_prob']})")
else:
    print(f"\n⚠ WARNING: Semantic probability is {result['semantic_analysis'].get('semantic_prob')}")
