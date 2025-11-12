"""
Mock CloudTrail Event Generator for Testing Threat Detection
Creates realistic fake CloudTrail events to populate your dashboard
"""

import json
from datetime import datetime, timedelta
import random
from collections import defaultdict


class MockCloudTrailGenerator:
    """Generate realistic mock CloudTrail events for testing"""
    
    def __init__(self):
        self.mock_buckets = [
            "production-data-bucket",
            "customer-uploads",
            "backup-archives",
            "logs-bucket",
            "public-assets"
        ]
        
        self.mock_users = [
            "admin@company.com",
            "developer@company.com", 
            "automated-service",
            "unknown-user",
            "external-contractor"
        ]
        
        self.mock_ips = [
            "203.0.113.42",  # Suspicious foreign IP
            "198.51.100.78",  # Normal corporate IP
            "52.95.128.0",    # AWS service IP
            "185.220.101.5",  # Tor exit node IP
            "10.0.1.100"      # Internal IP
        ]
        
        self.suspicious_user_agents = [
            "python-requests/2.28.0",  # Automated script
            "aws-cli/1.18.0",          # Old CLI version
            "curl/7.64.0",             # Manual curl access
            "boto3/1.26.0"             # SDK access
        ]
        
    def generate_mock_findings(self, scenario="mixed", hours=24):
        """
        Generate mock threat findings based on scenario
        
        Scenarios:
        - "clean": No threats (for baseline testing)
        - "critical": Multiple critical threats
        - "mixed": Variety of threat levels
        - "mass_deletion": Simulate ransomware attack
        - "policy_change": Simulate privilege escalation
        - "data_exfil": Simulate data exfiltration
        """
        
        findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "summary": {
                "total_events": 0,
                "suspicious_events": 0,
                "unique_buckets_accessed": [],
                "unique_ips": [],
                "scan_period_hours": hours,
                "critical_findings": 0,
                "high_findings": 0,
                "medium_findings": 0,
                "low_findings": 0
            }
        }
        
        if scenario == "clean":
            return self._generate_clean_scenario(findings, hours)
        elif scenario == "critical":
            return self._generate_critical_scenario(findings, hours)
        elif scenario == "mass_deletion":
            return self._generate_mass_deletion_scenario(findings, hours)
        elif scenario == "policy_change":
            return self._generate_policy_change_scenario(findings, hours)
        elif scenario == "data_exfil":
            return self._generate_data_exfil_scenario(findings, hours)
        else:  # mixed
            return self._generate_mixed_scenario(findings, hours)
    
    def _generate_clean_scenario(self, findings, hours):
        """No threats - clean environment"""
        findings["summary"]["total_events"] = random.randint(50, 150)
        findings["summary"]["unique_buckets_accessed"] = random.sample(self.mock_buckets, 3)
        findings["summary"]["unique_ips"] = [self.mock_ips[1], self.mock_ips[2]]  # Safe IPs
        return findings
    
    def _generate_critical_scenario(self, findings, hours):
        """Multiple critical threats"""
        now = datetime.utcnow()
        
        # 1. Bucket deletion attempt
        findings["critical"].append({
            "type": "high_risk_api_call",
            "event": "DeleteBucket",
            "bucket": self.mock_buckets[0],
            "user": self.mock_users[3],  # unknown-user
            "source_ip": self.mock_ips[0],  # Suspicious IP
            "time": (now - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S'),
            "user_agent": self.suspicious_user_agents[0],
            "success": False,
            "description": f"High-risk S3 API call: DeleteBucket on bucket {self.mock_buckets[0]}"
        })
        
        # 2. Public access block removal
        findings["critical"].append({
            "type": "high_risk_api_call",
            "event": "DeleteBucketPublicAccessBlock",
            "bucket": self.mock_buckets[1],
            "user": self.mock_users[4],  # external-contractor
            "source_ip": self.mock_ips[3],  # Tor exit node
            "time": (now - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'),
            "user_agent": self.suspicious_user_agents[2],
            "success": True,
            "description": f"High-risk S3 API call: DeleteBucketPublicAccessBlock on bucket {self.mock_buckets[1]}"
        })
        
        # 3. Mass deletion
        findings["critical"].append({
            "type": "mass_deletion",
            "bucket": self.mock_buckets[2],
            "deletion_count": 247,
            "time_period": f"Last {hours} hours",
            "description": f"Mass deletion detected: 247 objects deleted from {self.mock_buckets[2]}"
        })
        
        # 4. Bucket policy change
        findings["critical"].append({
            "type": "high_risk_api_call",
            "event": "PutBucketPolicy",
            "bucket": self.mock_buckets[1],
            "user": self.mock_users[3],
            "source_ip": self.mock_ips[0],
            "time": (now - timedelta(hours=3)).strftime('%Y-%m-%d %H:%M:%S'),
            "user_agent": self.suspicious_user_agents[1],
            "success": True,
            "description": f"High-risk S3 API call: PutBucketPolicy on bucket {self.mock_buckets[1]}"
        })
        
        findings["summary"]["total_events"] = 583
        findings["summary"]["suspicious_events"] = 4
        findings["summary"]["critical_findings"] = 4
        findings["summary"]["unique_buckets_accessed"] = self.mock_buckets[:3]
        findings["summary"]["unique_ips"] = self.mock_ips[:4]
        
        return findings
    
    def _generate_mass_deletion_scenario(self, findings, hours):
        """Simulate ransomware/mass deletion attack"""
        now = datetime.utcnow()
        
        # Multiple buckets affected
        findings["critical"].append({
            "type": "mass_deletion",
            "bucket": self.mock_buckets[0],
            "deletion_count": 1453,
            "time_period": f"Last {hours} hours",
            "user": self.mock_users[3],
            "source_ip": self.mock_ips[0],
            "description": f"Mass deletion detected: 1453 objects deleted from {self.mock_buckets[0]}"
        })
        
        findings["critical"].append({
            "type": "mass_deletion",
            "bucket": self.mock_buckets[1],
            "deletion_count": 892,
            "time_period": f"Last {hours} hours",
            "user": self.mock_users[3],
            "source_ip": self.mock_ips[0],
            "description": f"Mass deletion detected: 892 objects deleted from {self.mock_buckets[1]}"
        })
        
        findings["high"].append({
            "type": "elevated_deletion",
            "bucket": self.mock_buckets[2],
            "deletion_count": 34,
            "time_period": f"Last {hours} hours",
            "description": f"Elevated deletion activity: 34 objects deleted from {self.mock_buckets[2]}"
        })
        
        # Encryption disabled before deletion
        findings["critical"].append({
            "type": "high_risk_api_call",
            "event": "DeleteBucketEncryption",
            "bucket": self.mock_buckets[0],
            "user": self.mock_users[3],
            "source_ip": self.mock_ips[0],
            "time": (now - timedelta(hours=4)).strftime('%Y-%m-%d %H:%M:%S'),
            "user_agent": self.suspicious_user_agents[0],
            "success": True,
            "description": f"High-risk S3 API call: DeleteBucketEncryption on bucket {self.mock_buckets[0]}"
        })
        
        findings["summary"]["total_events"] = 2847
        findings["summary"]["suspicious_events"] = 4
        findings["summary"]["critical_findings"] = 3
        findings["summary"]["high_findings"] = 1
        findings["summary"]["unique_buckets_accessed"] = self.mock_buckets[:3]
        findings["summary"]["unique_ips"] = [self.mock_ips[0], self.mock_ips[1]]
        
        return findings
    
    def _generate_policy_change_scenario(self, findings, hours):
        """Simulate privilege escalation via policy changes"""
        now = datetime.utcnow()
        
        # Multiple policy changes
        for i, bucket in enumerate(self.mock_buckets[:3]):
            findings["high"].append({
                "type": "high_risk_api_call",
                "event": "PutBucketPolicy",
                "bucket": bucket,
                "user": self.mock_users[4],  # external-contractor
                "source_ip": self.mock_ips[0],
                "time": (now - timedelta(hours=i+1)).strftime('%Y-%m-%d %H:%M:%S'),
                "user_agent": self.suspicious_user_agents[1],
                "success": True,
                "description": f"High-risk S3 API call: PutBucketPolicy on bucket {bucket}"
            })
        
        # ACL changes
        findings["high"].append({
            "type": "high_risk_api_call",
            "event": "PutBucketAcl",
            "bucket": self.mock_buckets[1],
            "user": self.mock_users[4],
            "source_ip": self.mock_ips[0],
            "time": (now - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S'),
            "user_agent": self.suspicious_user_agents[1],
            "success": True,
            "description": f"High-risk S3 API call: PutBucketAcl on bucket {self.mock_buckets[1]}"
        })
        
        # Suspicious user activity
        findings["medium"].append({
            "type": "suspicious_user_activity",
            "user": self.mock_users[4],
            "high_risk_actions": 4,
            "total_actions": 12,
            "time_period": f"Last {hours} hours",
            "description": f"User {self.mock_users[4]} performed 4 high-risk S3 actions"
        })
        
        findings["summary"]["total_events"] = 247
        findings["summary"]["suspicious_events"] = 5
        findings["summary"]["high_findings"] = 4
        findings["summary"]["medium_findings"] = 1
        findings["summary"]["unique_buckets_accessed"] = self.mock_buckets[:3]
        findings["summary"]["unique_ips"] = [self.mock_ips[0], self.mock_ips[1]]
        
        return findings
    
    def _generate_data_exfil_scenario(self, findings, hours):
        """Simulate data exfiltration attempt"""
        now = datetime.utcnow()
        
        # Unusual access pattern from foreign IP
        findings["high"].append({
            "type": "unusual_access_pattern",
            "source_ip": self.mock_ips[0],
            "access_count": 1847,
            "time_period": f"Last {hours} hours",
            "buckets_accessed": [self.mock_buckets[0], self.mock_buckets[1]],
            "description": f"Unusual access pattern: 1847 S3 access calls from IP {self.mock_ips[0]}"
        })
        
        # Large number of GetObject calls
        findings["high"].append({
            "type": "unusual_access_pattern",
            "source_ip": self.mock_ips[3],  # Tor exit node
            "access_count": 523,
            "time_period": f"Last {hours} hours",
            "description": f"Unusual access pattern: 523 S3 access calls from IP {self.mock_ips[3]}"
        })
        
        # Suspicious user activity
        findings["medium"].append({
            "type": "suspicious_user_activity",
            "user": self.mock_users[3],
            "high_risk_actions": 3,
            "total_actions": 1892,
            "time_period": f"Last {hours} hours",
            "description": f"User {self.mock_users[3]} performed 3 high-risk S3 actions"
        })
        
        findings["summary"]["total_events"] = 2456
        findings["summary"]["suspicious_events"] = 3
        findings["summary"]["high_findings"] = 2
        findings["summary"]["medium_findings"] = 1
        findings["summary"]["unique_buckets_accessed"] = self.mock_buckets[:3]
        findings["summary"]["unique_ips"] = [self.mock_ips[0], self.mock_ips[3], self.mock_ips[1]]
        
        return findings
    
    def _generate_mixed_scenario(self, findings, hours):
        """Realistic mix of threats at different severity levels"""
        now = datetime.utcnow()
        
        # 1 Critical: Public access block removed
        findings["critical"].append({
            "type": "high_risk_api_call",
            "event": "DeleteBucketPublicAccessBlock",
            "bucket": self.mock_buckets[4],  # public-assets
            "user": self.mock_users[1],  # developer
            "source_ip": self.mock_ips[1],
            "time": (now - timedelta(hours=6)).strftime('%Y-%m-%d %H:%M:%S'),
            "user_agent": "aws-cli/2.9.0",
            "success": True,
            "description": f"High-risk S3 API call: DeleteBucketPublicAccessBlock on bucket {self.mock_buckets[4]}"
        })
        
        # 2 High: Elevated deletion activity
        findings["high"].append({
            "type": "elevated_deletion",
            "bucket": self.mock_buckets[2],
            "deletion_count": 28,
            "time_period": f"Last {hours} hours",
            "description": f"Elevated deletion activity: 28 objects deleted from {self.mock_buckets[2]}"
        })
        
        # 3 High: Policy change from unknown source
        findings["high"].append({
            "type": "high_risk_api_call",
            "event": "PutBucketPolicy",
            "bucket": self.mock_buckets[1],
            "user": self.mock_users[2],  # automated-service
            "source_ip": self.mock_ips[0],
            "time": (now - timedelta(hours=12)).strftime('%Y-%m-%d %H:%M:%S'),
            "user_agent": self.suspicious_user_agents[0],
            "success": True,
            "description": f"High-risk S3 API call: PutBucketPolicy on bucket {self.mock_buckets[1]}"
        })
        
        # 4 Medium: Suspicious user activity
        findings["medium"].append({
            "type": "suspicious_user_activity",
            "user": self.mock_users[4],
            "high_risk_actions": 3,
            "total_actions": 8,
            "time_period": f"Last {hours} hours",
            "description": f"User {self.mock_users[4]} performed 3 high-risk S3 actions"
        })
        
        # 5 Medium: Unusual access pattern (below critical threshold)
        findings["medium"].append({
            "type": "unusual_access_pattern",
            "source_ip": self.mock_ips[0],
            "access_count": 87,
            "time_period": f"Last {hours} hours",
            "description": f"Moderate access pattern: 87 S3 access calls from IP {self.mock_ips[0]}"
        })
        
        findings["summary"]["total_events"] = 456
        findings["summary"]["suspicious_events"] = 5
        findings["summary"]["critical_findings"] = 1
        findings["summary"]["high_findings"] = 2
        findings["summary"]["medium_findings"] = 2
        findings["summary"]["unique_buckets_accessed"] = self.mock_buckets
        findings["summary"]["unique_ips"] = self.mock_ips[:3]
        
        return findings


def get_mock_threat_findings(scenario="mixed", hours=24):
    """
    Main function to generate mock threat findings
    Use this in your dashboard for demo/testing
    """
    generator = MockCloudTrailGenerator()
    return generator.generate_mock_findings(scenario, hours)


if __name__ == "__main__":
    print("=" * 70)
    print("🎭 MOCK THREAT GENERATOR - Testing All Scenarios")
    print("=" * 70)
    
    scenarios = {
        "clean": "Clean Environment (No Threats)",
        "mixed": "Mixed Threats (Realistic)",
        "critical": "Multiple Critical Threats",
        "mass_deletion": "Ransomware Attack Simulation",
        "policy_change": "Privilege Escalation",
        "data_exfil": "Data Exfiltration Attempt"
    }
    
    for scenario_key, scenario_name in scenarios.items():
        print(f"\n{'=' * 70}")
        print(f"📊 Scenario: {scenario_name}")
        print('=' * 70)
        
        findings = get_mock_threat_findings(scenario=scenario_key, hours=24)
        
        print(f"Total Events: {findings['summary']['total_events']}")
        print(f"Suspicious Events: {findings['summary']['suspicious_events']}")
        print(f"🔴 Critical: {findings['summary']['critical_findings']}")
        print(f"🟠 High: {findings['summary']['high_findings']}")
        print(f"🟡 Medium: {findings['summary']['medium_findings']}")
        
        if findings['critical']:
            print(f"\n🚨 Critical Threats:")
            for f in findings['critical']:
                print(f"   • {f['description']}")
        
        if findings['high']:
            print(f"\n⚠️  High Priority Threats:")
            for f in findings['high']:
                print(f"   • {f['description']}")
        
        if findings['medium']:
            print(f"\n⚡ Medium Priority Threats:")
            for f in findings['medium']:
                print(f"   • {f['description']}")
    
    print("\n" + "=" * 70)
    print("✅ All scenarios generated successfully!")
    print("=" * 70)