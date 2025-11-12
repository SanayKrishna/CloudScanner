"""
Quick test script to see mock threats in action
Save as: test_demo_threats.py
Run: python test_demo_threats.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from utils.mock_threat_generator import get_mock_threat_findings

def display_findings(findings, scenario_name):
    """Pretty print threat findings"""
    print("\n" + "=" * 80)
    print(f"📊 SCENARIO: {scenario_name}")
    print("=" * 80)
    
    summary = findings['summary']
    print(f"\n📈 Summary:")
    print(f"   Total Events Analyzed: {summary['total_events']}")
    print(f"   Suspicious Events: {summary['suspicious_events']}")
    print(f"   🔴 Critical Findings: {summary['critical_findings']}")
    print(f"   🟠 High Priority: {summary['high_findings']}")
    print(f"   🟡 Medium Priority: {summary['medium_findings']}")
    
    if findings['critical']:
        print(f"\n🚨 CRITICAL THREATS:")
        for i, threat in enumerate(findings['critical'], 1):
            print(f"\n   {i}. {threat['type'].upper()}")
            print(f"      {threat['description']}")
            if 'user' in threat:
                print(f"      User: {threat['user']}")
            if 'source_ip' in threat:
                print(f"      IP: {threat['source_ip']}")
            if 'time' in threat:
                print(f"      Time: {threat['time']}")
    
    if findings['high']:
        print(f"\n⚠️  HIGH PRIORITY THREATS:")
        for i, threat in enumerate(findings['high'], 1):
            print(f"\n   {i}. {threat['type'].upper()}")
            print(f"      {threat['description']}")
    
    if findings['medium']:
        print(f"\n⚡ MEDIUM PRIORITY THREATS:")
        for i, threat in enumerate(findings['medium'], 1):
            print(f"\n   {i}. {threat['type'].upper()}")
            print(f"      {threat['description']}")
    
    if summary['suspicious_events'] == 0:
        print(f"\n✅ NO THREATS DETECTED - Clean environment!")
    
    print("\n" + "-" * 80)
    print(f"Unique Buckets: {', '.join(summary['unique_buckets_accessed'][:3])}")
    if len(summary['unique_buckets_accessed']) > 3:
        print(f"                ...and {len(summary['unique_buckets_accessed']) - 3} more")
    print(f"Unique IPs: {', '.join(summary['unique_ips'][:3])}")


def main():
    print("\n" + "🎭" * 40)
    print("MOCK THREAT DETECTION DEMO")
    print("🎭" * 40)
    
    scenarios = [
        ("clean", "Clean Environment (Baseline)"),
        ("mixed", "Realistic Mixed Threats"),
        ("critical", "High Alert - Multiple Critical Threats"),
        ("mass_deletion", "🚨 RANSOMWARE ATTACK SIMULATION"),
        ("policy_change", "Privilege Escalation Attempt"),
        ("data_exfil", "Data Exfiltration in Progress")
    ]
    
    print("\nAvailable Scenarios:")
    for i, (key, name) in enumerate(scenarios, 1):
        print(f"  {i}. {name}")
    
    print("\n" + "=" * 80)
    choice = input("Select scenario (1-6) or press Enter for all: ").strip()
    
    if choice and choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(scenarios):
            key, name = scenarios[idx]
            findings = get_mock_threat_findings(scenario=key, hours=24)
            display_findings(findings, name)
        else:
            print("Invalid choice!")
    else:
        # Show all scenarios
        for key, name in scenarios:
            findings = get_mock_threat_findings(scenario=key, hours=24)
            display_findings(findings, name)
    
    print("\n" + "=" * 80)
    print("✅ Demo complete!")
    print("=" * 80)
    print("\n💡 To use in your dashboard:")
    print("   1. Add ?demo=mixed to your threat detection URL")
    print("   2. Or set DEMO_MODE=true environment variable")
    print("   3. Available scenarios: clean, mixed, critical, mass_deletion, policy_change, data_exfil")
    print("\n📝 Example URLs:")
    print("   http://localhost:8000/api/threats?demo=critical")
    print("   http://localhost:8000/api/threats?demo=mass_deletion")
    print("   http://localhost:8000/threats (add ?demo=mixed to URL)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Demo cancelled")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()