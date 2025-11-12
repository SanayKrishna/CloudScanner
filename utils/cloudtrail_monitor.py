import boto3
import json
from datetime import datetime, timedelta
from collections import defaultdict
from botocore.exceptions import ClientError

class CloudTrailMonitor:
    """Monitor CloudTrail logs for suspicious S3 activity"""
    
    def __init__(self):
        self.cloudtrail = boto3.client('cloudtrail')
        self.s3 = boto3.client('s3')
        
        # Define suspicious S3 API calls
        self.high_risk_events = [
            'DeleteBucket',
            'DeleteBucketPolicy',
            'PutBucketPolicy',
            'PutBucketAcl',
            'DeleteBucketEncryption',
            'PutBucketPublicAccessBlock',
            'DeleteBucketPublicAccessBlock'
        ]
        
        self.data_access_events = [
            'GetObject',
            'ListObjects',
            'ListObjectsV2'
        ]
        
        self.deletion_events = [
            'DeleteObject',
            'DeleteObjects'
        ]
    
    def analyze_recent_activity(self, hours=24, max_results=1000):
        """
        Analyze CloudTrail logs for the last N hours
        Returns threat findings categorized by severity
        """
        findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "summary": {
                "total_events": 0,
                "suspicious_events": 0,
                "unique_buckets_accessed": set(),
                "unique_ips": set(),
                "scan_period_hours": hours
            }
        }
        
        try:
            # Calculate time range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            print(f"🔍 Analyzing CloudTrail logs from {start_time} to {end_time}")
            
            # Lookup CloudTrail events
            response = self.cloudtrail.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'ResourceType',
                        'AttributeValue': 'AWS::S3::Bucket'
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=max_results
            )
            
            events = response.get('Events', [])
            findings["summary"]["total_events"] = len(events)
            
            # Track patterns for anomaly detection
            user_activity = defaultdict(list)
            ip_activity = defaultdict(list)
            bucket_deletions = defaultdict(int)
            bucket_access = defaultdict(int)
            
            for event in events:
                event_name = event.get('EventName')
                username = event.get('Username', 'Unknown')
                event_time = event.get('EventTime')
                
                # Parse CloudTrail event
                cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                source_ip = cloud_trail_event.get('sourceIPAddress', 'Unknown')
                user_agent = cloud_trail_event.get('userAgent', 'Unknown')
                error_code = cloud_trail_event.get('errorCode')
                
                # Extract bucket name from resources
                bucket_name = self._extract_bucket_name(event, cloud_trail_event)
                
                if bucket_name:
                    findings["summary"]["unique_buckets_accessed"].add(bucket_name)
                
                if source_ip != 'Unknown':
                    findings["summary"]["unique_ips"].add(source_ip)
                
                # Track activity patterns
                user_activity[username].append(event_name)
                ip_activity[source_ip].append(event_name)
                
                # Detect suspicious activities
                
                # 1. High-risk configuration changes
                if event_name in self.high_risk_events:
                    severity = "critical" if event_name in ['DeleteBucket', 'PutBucketPolicy', 'DeleteBucketPublicAccessBlock'] else "high"
                    findings[severity].append({
                        "type": "high_risk_api_call",
                        "event": event_name,
                        "bucket": bucket_name,
                        "user": username,
                        "source_ip": source_ip,
                        "time": event_time.strftime('%Y-%m-%d %H:%M:%S'),
                        "user_agent": user_agent,
                        "success": error_code is None,
                        "description": f"High-risk S3 API call: {event_name} on bucket {bucket_name}"
                    })
                    findings["summary"]["suspicious_events"] += 1
                
                # 2. Mass deletions
                if event_name in self.deletion_events:
                    bucket_deletions[bucket_name] += 1
                
                # 3. Unusual access patterns
                if event_name in self.data_access_events:
                    bucket_access[bucket_name] += 1
            
            # Analyze patterns for anomalies
            
            # Detect mass deletions (threshold: 50+ deletions)
            for bucket, count in bucket_deletions.items():
                if count >= 50:
                    findings["critical"].append({
                        "type": "mass_deletion",
                        "bucket": bucket,
                        "deletion_count": count,
                        "time_period": f"Last {hours} hours",
                        "description": f"Mass deletion detected: {count} objects deleted from {bucket}"
                    })
                    findings["summary"]["suspicious_events"] += 1
                elif count >= 20:
                    findings["high"].append({
                        "type": "elevated_deletion",
                        "bucket": bucket,
                        "deletion_count": count,
                        "time_period": f"Last {hours} hours",
                        "description": f"Elevated deletion activity: {count} objects deleted from {bucket}"
                    })
                    findings["summary"]["suspicious_events"] += 1
            
            # Detect unusual access patterns (threshold: 100+ access calls from single IP)
            for ip, events_list in ip_activity.items():
                access_count = sum(1 for e in events_list if e in self.data_access_events)
                if access_count >= 100 and not self._is_aws_service_ip(ip):
                    findings["high"].append({
                        "type": "unusual_access_pattern",
                        "source_ip": ip,
                        "access_count": access_count,
                        "time_period": f"Last {hours} hours",
                        "description": f"Unusual access pattern: {access_count} S3 access calls from IP {ip}"
                    })
                    findings["summary"]["suspicious_events"] += 1
            
            # Detect suspicious user activity (multiple high-risk actions)
            for user, events_list in user_activity.items():
                high_risk_count = sum(1 for e in events_list if e in self.high_risk_events)
                if high_risk_count >= 3:
                    findings["medium"].append({
                        "type": "suspicious_user_activity",
                        "user": user,
                        "high_risk_actions": high_risk_count,
                        "total_actions": len(events_list),
                        "time_period": f"Last {hours} hours",
                        "description": f"User {user} performed {high_risk_count} high-risk S3 actions"
                    })
                    findings["summary"]["suspicious_events"] += 1
            
            # Convert sets to lists for JSON serialization
            findings["summary"]["unique_buckets_accessed"] = list(findings["summary"]["unique_buckets_accessed"])
            findings["summary"]["unique_ips"] = list(findings["summary"]["unique_ips"])
            
            # Add statistics
            findings["summary"]["critical_findings"] = len(findings["critical"])
            findings["summary"]["high_findings"] = len(findings["high"])
            findings["summary"]["medium_findings"] = len(findings["medium"])
            findings["summary"]["low_findings"] = len(findings["low"])
            
            print(f"✅ Analysis complete: {findings['summary']['suspicious_events']} suspicious events found")
            
            return findings
            
        except ClientError as e:
            print(f"❌ Error analyzing CloudTrail: {e}")
            return {
                "error": str(e),
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "summary": {}
            }
    
    def get_bucket_activity(self, bucket_name, hours=24):
        """Get all CloudTrail activity for a specific bucket"""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            response = self.cloudtrail.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'ResourceType',
                        'AttributeValue': 'AWS::S3::Bucket'
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=1000
            )
            
            bucket_events = []
            for event in response.get('Events', []):
                cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                event_bucket = self._extract_bucket_name(event, cloud_trail_event)
                
                if event_bucket == bucket_name:
                    bucket_events.append({
                        "event_name": event.get('EventName'),
                        "user": event.get('Username'),
                        "time": event.get('EventTime').strftime('%Y-%m-%d %H:%M:%S'),
                        "source_ip": cloud_trail_event.get('sourceIPAddress', 'Unknown'),
                        "success": cloud_trail_event.get('errorCode') is None
                    })
            
            return {
                "bucket": bucket_name,
                "events": bucket_events,
                "event_count": len(bucket_events),
                "time_period": f"Last {hours} hours"
            }
            
        except ClientError as e:
            print(f"Error fetching bucket activity: {e}")
            return {"error": str(e)}
    
    def _extract_bucket_name(self, event, cloud_trail_event):
        """Extract bucket name from CloudTrail event"""
        # Try to get from resources
        resources = event.get('Resources', [])
        for resource in resources:
            if resource.get('ResourceType') == 'AWS::S3::Bucket':
                return resource.get('ResourceName')
        
        # Try to parse from request parameters
        request_params = cloud_trail_event.get('requestParameters', {})
        if 'bucketName' in request_params:
            return request_params['bucketName']
        
        # Try to parse from ARN in resources
        for resource in resources:
            resource_name = resource.get('ResourceName', '')
            if resource_name.startswith('arn:aws:s3:::'):
                return resource_name.replace('arn:aws:s3:::', '').split('/')[0]
        
        return None
    
    def _is_aws_service_ip(self, ip):
        """Check if IP belongs to AWS services"""
        aws_service_indicators = [
            'amazonaws.com',
            'AWS Internal'
        ]
        return any(indicator in ip for indicator in aws_service_indicators)


# Cache for storing recent findings
_threat_cache = {
    "last_scan": None,
    "findings": None
}

def get_threat_findings(hours=24, force_refresh=False):
    """Get threat findings with caching"""
    global _threat_cache
    
    # Check if we need to refresh
    if force_refresh or _threat_cache["last_scan"] is None:
        monitor = CloudTrailMonitor()
        findings = monitor.analyze_recent_activity(hours=hours)
        
        _threat_cache["last_scan"] = datetime.utcnow()
        _threat_cache["findings"] = findings
        
        return findings
    
    # Check if cache is still valid (refresh every 5 minutes)
    if (datetime.utcnow() - _threat_cache["last_scan"]).seconds > 300:
        monitor = CloudTrailMonitor()
        findings = monitor.analyze_recent_activity(hours=hours)
        
        _threat_cache["last_scan"] = datetime.utcnow()
        _threat_cache["findings"] = findings
        
        return findings
    
    return _threat_cache["findings"]


def get_bucket_threat_activity(bucket_name, hours=24):
    """Get threat activity for a specific bucket"""
    monitor = CloudTrailMonitor()
    return monitor.get_bucket_activity(bucket_name, hours=hours)


if __name__ == "__main__":
    print("🔍 Starting CloudTrail Threat Detection...")
    monitor = CloudTrailMonitor()
    findings = monitor.analyze_recent_activity(hours=24)
    
    print("\n📊 Threat Detection Summary:")
    print(f"Total Events: {findings['summary']['total_events']}")
    print(f"Suspicious Events: {findings['summary']['suspicious_events']}")
    print(f"Critical Findings: {findings['summary']['critical_findings']}")
    print(f"High Findings: {findings['summary']['high_findings']}")
    print(f"Medium Findings: {findings['summary']['medium_findings']}")
    
    if findings['critical']:
        print("\n🚨 CRITICAL THREATS:")
        for finding in findings['critical']:
            print(f"  - {finding['description']}")
    
    if findings['high']:
        print("\n⚠️  HIGH PRIORITY THREATS:")
        for finding in findings['high']:
            print(f"  - {finding['description']}")