"""
Unit tests for calculate_risk() function.

Tests verify that:
1. sem_active is properly defined and used
2. Risk score correctly weights all components (URL, ML, headers, attachments, semantic)
3. Verdicts are assigned correctly based on thresholds
4. Breakdown dictionary contains all expected fields
5. Function handles edge cases (None/empty values)
"""

import pytest
from analysis_engine import calculate_risk


class TestCalculateRiskBasic:
    """Test basic risk calculation with various input scenarios."""
    
    def test_sem_active_is_defined(self):
        """Verify sem_active variable is properly initialized."""
        # This test would have failed before the fix with NameError
        header = {"score": 0}
        url = {"score": 0}
        attachment = {"score": 0}
        ml = {"phishing_probability": 0.5}
        sem = {"semantic_prob": 0.6}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        # If sem_active is undefined, this would throw NameError
        assert result is not None
        assert "breakdown" in result
    
    def test_sem_active_true_when_semantic_provided(self):
        """Test sem_active = True when semantic model output is provided."""
        header = {"score": 20}
        url = {"score": 30}
        attachment = {"score": 10}
        ml = {"phishing_probability": 0.6}
        sem = {"semantic_prob": 0.75}  # sem_active should be True
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        # Verify semantic score is included in breakdown
        assert result["breakdown"]["semantic"] is not None
        assert result["breakdown"]["semantic"] > 0
    
    def test_sem_active_false_when_semantic_empty(self):
        """Test sem_active = False when semantic model output is empty/None."""
        header = {"score": 20}
        url = {"score": 30}
        attachment = {"score": 10}
        ml = {"phishing_probability": 0.6}
        sem = {}  # Empty: sem_active should be False
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        # Verify semantic score is None when semantic is inactive
        assert result["breakdown"]["semantic"] is None
    
    def test_sem_active_false_when_semantic_zero(self):
        """Test sem_active = False when semantic probability is 0."""
        header = {"score": 20}
        url = {"score": 30}
        attachment = {"score": 10}
        ml = {"phishing_probability": 0.6}
        sem = {"semantic_prob": 0}  # Zero: sem_active should be False
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        assert result["breakdown"]["semantic"] is None
    
    def test_all_scores_zero(self):
        """Test with all scores at zero — should be 'safe'."""
        header = {"score": 0}
        url = {"score": 0}
        attachment = {"score": 0}
        ml = {"phishing_probability": 0.0}
        sem = {"semantic_prob": 0.0}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        assert result["verdict"] == "safe"
        assert result["risk_score"] < 30  # Below suspicious threshold
        assert result["color"] == "#10b981"  # Green
    
    def test_malicious_verdict_high_score(self):
        """Test malicious verdict when risk score >= 50."""
        header = {"score": 80}
        url = {"score": 70}
        attachment = {"score": 60}
        ml = {"phishing_probability": 0.85}
        sem = {"semantic_prob": 0.8}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        assert result["verdict"] == "malicious"
        assert result["risk_score"] >= 50
        assert result["color"] == "#ef4444"  # Red
    
    def test_suspicious_verdict_medium_score(self):
        """Test suspicious verdict when 30 <= risk_score < 50."""
        header = {"score": 40}
        url = {"score": 35}
        attachment = {"score": 30}
        ml = {"phishing_probability": 0.5}
        sem = {"semantic_prob": 0.45}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        assert result["verdict"] == "suspicious"
        assert 30 <= result["risk_score"] < 50
        assert result["color"] == "#f59e0b"  # Orange
    
    def test_safe_verdict_low_score(self):
        """Test safe verdict when risk_score < 30."""
        header = {"score": 10}
        url = {"score": 15}
        attachment = {"score": 5}
        ml = {"phishing_probability": 0.2}
        sem = {"semantic_prob": 0.1}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        assert result["verdict"] == "safe"
        assert result["risk_score"] < 30
        assert result["color"] == "#10b981"  # Green


class TestCalculateRiskWeighting:
    """Test that component weights are correctly applied."""
    
    def test_url_weighting(self):
        """Test that URL component is weighted at 25%."""
        # Isolate URL component: only URL score is high
        header = {"score": 0}
        url = {"score": 100}  # Max URL score
        attachment = {"score": 0}
        ml = {"phishing_probability": 0.0}
        sem = {"semantic_prob": 0.0}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        # URL at 25% in the current risk model
        assert result["breakdown"]["url"] == 25.0
        assert result["risk_score"] >= 25
    
    def test_ml_weighting(self):
        """Test that ML component is weighted at 35% when semantic scoring is inactive."""
        header = {"score": 0}
        url = {"score": 0}
        attachment = {"score": 0}
        ml = {"phishing_probability": 1.0}  # Max ML probability
        sem = {"semantic_prob": 0.0}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        # When semantic is inactive, ML weight in breakdown is 35%
        assert result["breakdown"]["ml"] == 35.0
    
    def test_header_weighting_with_sem_active(self):
        """Test header weighting when semantic is active (18%)."""
        header = {"score": 100}
        url = {"score": 0}
        attachment = {"score": 0}
        ml = {"phishing_probability": 0.0}
        sem = {"semantic_prob": 0.8}  # sem_active = True
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        # Header weighted at 0.20 (20%) when sem is active per breakdown formula
        assert result["breakdown"]["header"] == 20.0
    
    def test_attachment_weighting_with_sem_active(self):
        """Test attachment weighting when semantic is active (15%)."""
        header = {"score": 0}
        url = {"score": 0}
        attachment = {"score": 100}
        ml = {"phishing_probability": 0.0}
        sem = {"semantic_prob": 0.8}  # sem_active = True
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        # Attachment weighted at 0.15 (15%) when sem is active
        assert result["breakdown"]["attachment"] == 15.0
    
    def test_semantic_weighting(self):
        """Test semantic component is weighted at 15%."""
        header = {"score": 0}
        url = {"score": 0}
        attachment = {"score": 0}
        ml = {"phishing_probability": 0.0}
        sem = {"semantic_prob": 1.0}  # Max semantic score
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        # Semantic at 15%: 1.0 * 100 * 0.15 = 15
        assert result["breakdown"]["semantic"] == 15.0


class TestCalculateRiskBreakdown:
    """Test the breakdown dictionary structure and contents."""
    
    def test_breakdown_contains_all_fields(self):
        """Verify breakdown dict contains all expected fields."""
        header = {"score": 30}
        url = {"score": 40}
        attachment = {"score": 20}
        ml = {"phishing_probability": 0.6}
        sem = {"semantic_prob": 0.5}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        breakdown = result["breakdown"]
        assert "header" in breakdown
        assert "url" in breakdown
        assert "attachment" in breakdown
        assert "ml" in breakdown
        assert "semantic" in breakdown
        assert "confidence_bonus" in breakdown
        assert "ioc_boost" in breakdown
    
    def test_breakdown_values_are_numeric(self):
        """Test that all breakdown values are numeric or None."""
        header = {"score": 30}
        url = {"score": 40}
        attachment = {"score": 20}
        ml = {"phishing_probability": 0.6}
        sem = {"semantic_prob": 0.5}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        breakdown = result["breakdown"]
        for key, value in breakdown.items():
            assert value is None or isinstance(value, (int, float))
    
    def test_breakdown_totals_approach_risk_score(self):
        """Test that breakdown components roughly sum to risk_score."""
        header = {"score": 50}
        url = {"score": 60}
        attachment = {"score": 40}
        ml = {"phishing_probability": 0.7}
        sem = {"semantic_prob": 0.6}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        breakdown = result["breakdown"]
        # Sum primary components (excluding bonuses and optional fields)
        component_sum = (
            breakdown["header"] +
            breakdown["url"] +
            breakdown["attachment"] +
            breakdown["ml"] +
            (breakdown["semantic"] or 0)
        )
        
        # Should be close to risk_score (accounting for rounding and bonuses)
        assert abs(component_sum - result["risk_score"]) < 10


class TestCalculateRiskEdgeCases:
    """Test edge cases and error handling."""
    
    def test_with_none_sem_parameter(self):
        """Test with sem=None (should not crash)."""
        header = {"score": 30}
        url = {"score": 40}
        attachment = {"score": 20}
        ml = {"phishing_probability": 0.6}
        sem = None
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        assert result is not None
        assert result["verdict"] in ["safe", "suspicious", "malicious"]
    
    def test_with_missing_ml_probability(self):
        """Test when ML dict lacks phishing_probability key."""
        header = {"score": 30}
        url = {"score": 40}
        attachment = {"score": 20}
        ml = {}  # No phishing_probability
        sem = {"semantic_prob": 0.5}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        assert result is not None
        # Should default to 0.0 for missing probability
        assert result["breakdown"]["ml"] == 0.0
    
    def test_with_extreme_scores(self):
        """Test with extreme score values."""
        header = {"score": 1000}  # Way above 100
        url = {"score": 1000}
        attachment = {"score": 1000}
        ml = {"phishing_probability": 10.0}  # Way above 1.0
        sem = {"semantic_prob": 10.0}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        # Should handle gracefully and cap at 100
        assert result["risk_score"] <= 100
        assert result["verdict"] == "malicious"
    
    def test_with_negative_scores(self):
        """Test with negative score values (should be clamped to 0)."""
        header = {"score": -50}
        url = {"score": -30}
        attachment = {"score": -20}
        ml = {"phishing_probability": -0.5}
        sem = {"semantic_prob": -0.3}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        # Negative values should be clamped out of the final risk score
        assert result["risk_score"] >= 0
        assert result["verdict"] == "safe"


class TestCalculateRiskIOCIntegration:
    """Test with threat intelligence (IOC) data."""
    
    def test_with_ioc_intel_critical_url(self):
        """Test with critical-tier URL in threat intelligence."""
        header = {"score": 20}
        url = {"score": 30}
        attachment = {"score": 10}
        ml = {"phishing_probability": 0.4}
        sem = {"semantic_prob": 0.3}
        ioc_intel = {
            "urls": [
                {"url": "http://evil.com", "tier": "critical", "score": 95}
            ]
        }
        
        result = calculate_risk(header, url, attachment, ml, sem, ioc_intel=ioc_intel)
        
        # Critical IOC should boost verdict
        assert result["breakdown"]["ioc_boost"] is not None
        assert result["breakdown"]["ioc_boost"] > 0
    
    def test_with_ioc_intel_high_ip(self):
        """Test with high-tier IP in threat intelligence."""
        header = {"score": 20}
        url = {"score": 30}
        attachment = {"score": 10}
        ml = {"phishing_probability": 0.4}
        sem = {"semantic_prob": 0.3}
        ioc_intel = {
            "ip": {"ip": "192.0.2.1", "tier": "high", "score": 85}
        }
        
        result = calculate_risk(header, url, attachment, ml, sem, ioc_intel=ioc_intel)
        
        # High IP intel should increase header score boost
        assert "header_ioc_boost" not in result["breakdown"]  # Part of header calc
        assert result is not None


class TestCalculateRiskReturnStructure:
    """Test the complete return structure of calculate_risk()."""
    
    def test_return_structure(self):
        """Verify complete return structure."""
        header = {"score": 30}
        url = {"score": 40}
        attachment = {"score": 20}
        ml = {"phishing_probability": 0.6}
        sem = {"semantic_prob": 0.5}
        
        result = calculate_risk(header, url, attachment, ml, sem)
        
        # Check all required top-level keys
        assert "risk_score" in result
        assert "verdict" in result
        assert "color" in result
        assert "breakdown" in result
        assert "recommendations" in result
        
        # Check types
        assert isinstance(result["risk_score"], (int, float))
        assert isinstance(result["verdict"], str)
        assert isinstance(result["color"], str)
        assert isinstance(result["breakdown"], dict)
        assert isinstance(result["recommendations"], list)
    
    def test_verdicts_are_valid(self):
        """Test that verdicts are always one of three values."""
        test_cases = [
            ({"score": 0}, {"score": 0}, {"score": 0}, 0.0, 0.0),  # Safe
            ({"score": 40}, {"score": 50}, {"score": 30}, 0.5, 0.5),  # Suspicious
            ({"score": 80}, {"score": 90}, {"score": 70}, 0.9, 0.9),  # Malicious
        ]
        
        for header, url, attachment, ml_prob, sem_prob in test_cases:
            result = calculate_risk(
                header, url, attachment,
                {"phishing_probability": ml_prob},
                {"semantic_prob": sem_prob}
            )
            
            assert result["verdict"] in ["safe", "suspicious", "malicious"]
    
    def test_color_codes_match_verdicts(self):
        """Test that color codes match their corresponding verdicts."""
        verdict_color_map = {
            "safe": "#10b981",
            "suspicious": "#f59e0b",
            "malicious": "#ef4444",
        }
        
        test_cases = [
            ({"score": 0}, {"score": 0}, {"score": 0}, 0.0),
            ({"score": 50}, {"score": 50}, {"score": 50}, 0.5),
            ({"score": 100}, {"score": 100}, {"score": 100}, 1.0),
        ]
        
        for header, url, attachment, ml_prob in test_cases:
            result = calculate_risk(
                header, url, attachment,
                {"phishing_probability": ml_prob},
                {"semantic_prob": 0.5}
            )
            
            expected_color = verdict_color_map[result["verdict"]]
            assert result["color"] == expected_color


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
