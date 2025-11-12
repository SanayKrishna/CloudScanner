"""
Test script for CloudTrail threat detection
Run this to verify your threat detection is working
"""

import sys
import os

# Add utils directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'utils'))

from cloudtrail_monitor import CloudTrailMonitor

def test_threat_detection():
    print("=" * 60)
    print("🔍 Testing CloudTrail Threat Detection")
    print("=" * 60)
    
    monitor = CloudTrailMonitor()
    
    # Test 1: Analyze recent activity
    print("\n📊 Test 1: Analyzing last 24 hours of activity...")
    findings = monitor.analyze_recent_activity(hours=24)
    
    print(f"\n✅ Total Events Analyzed: {findings['summary']['total_events']}")
    print(f"⚠️  Suspicious Events Found: {findings['summary']['suspicious_events']}")
    print(f"🔴 Critical Findings: {findings['summary']['critical_findings']}")
    print(f"🟠 High Priority Findings: {findings['summary']['high_findings']}")
    print(f"🟡 Medium Priority Findings: {findings['summary']['medium_findings']}")
    
    # Display critical findings
    if findings['critical']:
        print("\n" + "=" * 60)
        print("🚨 CRITICAL THREATS DETECTED:")
        print("=" * 60)
        for i, finding in enumerate(findings['critical'], 1):
            print(f"\n{i}. {finding['type'].upper()}")
            print(f"   Description: {finding['description']}")
            if 'bucket' in finding:
                print(f"   Bucket: {finding['bucket']}")
            if 'user' in finding:
                print(f"   User: {finding['user']}")
            if 'source_ip' in finding:
                print(f"   Source IP: {finding['source_ip']}")
    
    # Display high priority findings
    if findings['high']:
        print("\n" + "=" * 60)
        print("⚠️  HIGH PRIORITY THREATS:")
        print("=" * 60)
        for i, finding in enumerate(findings['high'], 1):
            print(f"\n{i}. {finding['type'].upper()}")
            print(f"   Description: {finding['description']}")
    
    # Display medium priority findings
    if findings['medium']:
        print("\n" + "=" * 60)
        print("⚡ MEDIUM PRIORITY THREATS:")
        print("=" * 60)
        for i, finding in enumerate(findings['medium'], 1):
            print(f"\n{i}. {finding['type'].upper()}")
            print(f"   Description: {finding['description']}")
    
    # If no threats found
    if findings['summary']['suspicious_events'] == 0:
        print("\n" + "=" * 60)
        print("✅ NO THREATS DETECTED")
        print("=" * 60)
        print("Your S3 buckets show no suspicious activity!")
    
    # Test 2: Check unique statistics
    print("\n" + "=" * 60)
    print("📈 Activity Statistics:")
    print("=" * 60)
    print(f"Unique Buckets Accessed: {len(findings['summary']['unique_buckets_accessed'])}")
    print(f"Unique Source IPs: {len(findings['summary']['unique_ips'])}")
    
    if findings['summary']['unique_buckets_accessed']:
        print(f"\nBuckets: {', '.join(findings['summary']['unique_buckets_accessed'][:5])}")
        if len(findings['summary']['unique_buckets_accessed']) > 5:
            print(f"... and {len(findings['summary']['unique_buckets_accessed']) - 5} more")
    
    print("\n" + "=" * 60)
    print("✅ Threat Detection Test Complete!")
    print("=" * 60)

if __name__ == "__main__":
    try:
        test_threat_detection()
    except Exception as e:
        print(f"\n❌ Error during testing: {str(e)}")
        print("\nMake sure:")
        print("1. AWS credentials are configured")
        print("2. CloudTrail is enabled in your AWS account")
        print("3. You have permissions to read CloudTrail logs")
        import traceback
        traceback.print_exc()