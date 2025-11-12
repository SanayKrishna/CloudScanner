"""
Detailed S3 audit module.

Provides:
- audit_bucket(bucket_name, s3_client, deep_object_check=False, max_objects=50)
    -> returns dict with bucket metadata, issues[], and attributes (encryption, logging, versioning, replication, policy, acl)

- scan_all_buckets_detailed(deep_object_check=False, max_objects_per_bucket=50)
    -> orchestrates scanning of all buckets and returns { "buckets": {name: bucket_result}, "summary": {...} }

Notes:
- deep_object_check is optional and may incur many API calls; default is False.
- ensure AWS credentials and permissions allow the following API calls:
  ListBuckets, GetBucketPolicy, GetBucketAcl, GetBucketEncryption, GetBucketLogging,
  GetBucketVersioning, GetBucketReplication, ListObjectsV2, GetObjectAcl
"""

import boto3
from botocore.exceptions import ClientError
from .compliance_mapper import get_compliance
import json
import logging

logger = logging.getLogger(__name__)


# Severity classification sets (easy to customize)
_CRITICAL = {"public_bucket_policy", "public_acl", "object_public_acl", "encryption_missing"}
_WARNING = {"logging_disabled", "versioning_disabled"}
_INFO = {"replication_disabled", "block_public_access"}


def _severity_for(issue_id):
    if issue_id in _CRITICAL:
        return "CRITICAL"
    if issue_id in _WARNING:
        return "WARNING"
    return "INFO"


def _acl_is_public(grants):
    """
    Return (True, uri) if ACL grants include AllUsers or AuthenticatedUsers.
    """
    PUBLIC_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
    AUTH_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
    for grant in grants or []:
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI")
        if uri in (PUBLIC_URI, AUTH_URI):
            return True, uri
    return False, None


def audit_bucket(bucket_name, s3_client, deep_object_check=False, max_objects=50):
    """
    Audit single bucket. Returns a dict describing issues and metadata.
    """
    result = {
        "name": bucket_name,
        "issues": [],             # list of { id, severity, message, compliance:[], remediation }
        "encryption": None,       # { status: "SSE-S3"|"SSE-KMS"|"NONE"|"UNKNOWN", kms_key_id: ... }
        "logging": None,          # { enabled: True/False, target_bucket: ... }
        "versioning": None,       # { status: "Enabled"|"Suspended"|"Disabled" }
        "replication": None,      # { enabled: True/False, rules: [...] }
        "policy": None,
        "acl": None,
        "_errors": []
    }

    # 1) Bucket Policy
    try:
        resp = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_text = resp.get("Policy")
        if policy_text:
            policy = json.loads(policy_text)
            result["policy"] = policy
            for stmt in policy.get("Statement", []):
                effect = stmt.get("Effect", "").lower()
                if effect != "allow":
                    continue
                principal = stmt.get("Principal")
                actions = stmt.get("Action") or []
                if isinstance(actions, str):
                    actions = [actions]
                # determine if policy uses wildcard principal
                is_public_principal = False
                if principal == "*" or principal == {"AWS": "*"}:
                    is_public_principal = True
                elif isinstance(principal, dict):
                    for v in principal.values():
                        if v == "*" or (isinstance(v, list) and "*" in v):
                            is_public_principal = True
                if is_public_principal:
                    for a in actions:
                        if isinstance(a, str) and ("GetObject" in a or a == "*" or "s3:*" in a):
                            meta = get_compliance("public_bucket_policy")
                            issue = {
                                "id": "public_bucket_policy",
                                "severity": _severity_for("public_bucket_policy"),
                                "message": "Bucket policy allows public object access (Principal=* with GetObject/wildcard).",
                                "compliance": meta.get("compliance", []),
                                "remediation": meta.get("remediation", "")
                            }
                            result["issues"].append(issue)
                            break
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code not in ("NoSuchBucketPolicy", "AccessDenied"):
            result["_errors"].append(f"get_bucket_policy_error:{str(e)}")

    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        result["acl"] = acl
        grants = acl.get("Grants", [])
        public_acl, uri = _acl_is_public(grants)
        if public_acl:
            meta = get_compliance("public_acl")
            result["issues"].append({
                "id": "public_acl",
                "severity": _severity_for("public_acl"),
                "message": f"Bucket ACL grants public access ({uri}).",
                "compliance": meta.get("compliance", []),
                "remediation": meta.get("remediation", "")
            })
    except ClientError as e:
        result["_errors"].append(f"get_bucket_acl_error:{str(e)}")

    try:
        enc = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            r = rules[0]
            algo = r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
            kms_id = r.get("ApplyServerSideEncryptionByDefault", {}).get("KMSMasterKeyID")
            result["encryption"] = {"status": algo or "UNKNOWN", "kms_key_id": kms_id}
        else:
            result["encryption"] = {"status": "UNKNOWN", "kms_key_id": None}
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchEncryptionConfiguration"):
            result["encryption"] = {"status": "NONE", "kms_key_id": None}
            meta = get_compliance("encryption_missing")
            result["issues"].append({
                "id": "encryption_missing",
                "severity": _severity_for("encryption_missing"),
                "message": "No default server-side encryption configured for bucket.",
                "compliance": meta.get("compliance", []),
                "remediation": meta.get("remediation", "")
            })
        else:
            result["_errors"].append(f"get_bucket_encryption_error:{str(e)}")

    try:
        logging_conf = s3_client.get_bucket_logging(Bucket=bucket_name)
        if logging_conf.get("LoggingEnabled"):
            result["logging"] = {"enabled": True, "target_bucket": logging_conf["LoggingEnabled"].get("TargetBucket")}
        else:
            result["logging"] = {"enabled": False}
            meta = get_compliance("logging_disabled")
            result["issues"].append({
                "id": "logging_disabled",
                "severity": _severity_for("logging_disabled"),
                "message": "Server access logging is not enabled.",
                "compliance": meta.get("compliance", []),
                "remediation": meta.get("remediation", "")
            })
    except ClientError as e:
        result["_errors"].append(f"get_bucket_logging_error:{str(e)}")

    try:
        ver = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = ver.get("Status") or "Disabled"
        result["versioning"] = {"status": status}
        if status != "Enabled":
            meta = get_compliance("versioning_disabled")
            result["issues"].append({
                "id": "versioning_disabled",
                "severity": _severity_for("versioning_disabled"),
                "message": "Bucket versioning is not enabled.",
                "compliance": meta.get("compliance", []),
                "remediation": meta.get("remediation", "")
            })
    except ClientError as e:
        result["_errors"].append(f"get_bucket_versioning_error:{str(e)}")

    try:
        repl = s3_client.get_bucket_replication(Bucket=bucket_name)
        rules = repl.get("ReplicationConfiguration", {}).get("Rules", [])
        if rules:
            result["replication"] = {"enabled": True, "rules": rules}
        else:
            result["replication"] = {"enabled": False}
            meta = get_compliance("replication_disabled")
            result["issues"].append({
                "id": "replication_disabled",
                "severity": _severity_for("replication_disabled"),
                "message": "Bucket replication (CRR) is not configured.",
                "compliance": meta.get("compliance", []),
                "remediation": meta.get("remediation", "")
            })
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("ReplicationConfigurationNotFoundError",):
            result["replication"] = {"enabled": False}
            meta = get_compliance("replication_disabled")
            result["issues"].append({
                "id": "replication_disabled",
                "severity": _severity_for("replication_disabled"),
                "message": "Bucket replication (CRR) is not configured.",
                "compliance": meta.get("compliance", []),
                "remediation": meta.get("remediation", "")
            })
        else:
            result["_errors"].append(f"get_bucket_replication_error:{str(e)}")

    if deep_object_check:
        try:
            paginator = s3_client.get_paginator("list_objects_v2")
            scanned = 0
            for page in paginator.paginate(Bucket=bucket_name):
                for obj in page.get("Contents", []):
                    if scanned >= max_objects:
                        break
                    key = obj.get("Key")
                    try:
                        obj_acl = s3_client.get_object_acl(Bucket=bucket_name, Key=key)
                        public, uri = _acl_is_public(obj_acl.get("Grants", []))
                        if public:
                            meta = get_compliance("object_public_acl")
                            result["issues"].append({
                                "id": "object_public_acl",
                                "severity": _severity_for("object_public_acl"),
                                "message": f"Object '{key}' has public ACL ({uri}).",
                                "compliance": meta.get("compliance", []),
                                "remediation": meta.get("remediation", "")
                            })
                    except ClientError as e:
                        result["_errors"].append(f"get_object_acl_error:{key}:{str(e)}")
                    scanned += 1
                if scanned >= max_objects:
                    break
        except ClientError as e:
            result["_errors"].append(f"list_objects_error:{str(e)}")

    seen = set()
    unique = []
    for issue in result["issues"]:
        if issue["id"] not in seen:
            unique.append(issue)
            seen.add(issue["id"])
    result["issues"] = unique

    return result


def scan_all_buckets_detailed(deep_object_check=False, max_objects_per_bucket=50):
    s3 = boto3.client("s3")
    results = {
        "buckets": {}, 
        "summary": {
            "total_buckets": 0,
            "critical": 0,
            "warning": 0,
            "info": 0,
            "buckets_with_critical": set(),
            "buckets_with_warning": set(),
            "buckets_with_info": set()
        }
    }

    try:
        resp = s3.list_buckets()
        buckets = [b["Name"] for b in resp.get("Buckets", [])]
    except ClientError as e:
        results["_error"] = f"list_buckets_failed:{str(e)}"
        return results
    except Exception as e:
        results["_error"] = f"unexpected_list_buckets_error:{str(e)}"
        return results

    results["summary"]["total_buckets"] = len(buckets)

    for name in buckets:
        try:
            b_res = audit_bucket(name, s3, deep_object_check=deep_object_check, max_objects=max_objects_per_bucket)
            results["buckets"][name] = b_res
            has_critical = False
            has_warning = False
            has_info = False
            
            for issue in b_res.get("issues", []):
                sev = issue.get("severity", "INFO")
                if sev == "CRITICAL":
                    has_critical = True
                elif sev == "WARNING":
                    has_warning = True
                else:
                    has_info = True
            
            if has_critical:
                results["summary"]["buckets_with_critical"].add(name)
            if has_warning:
                results["summary"]["buckets_with_warning"].add(name)
            if has_info:
                results["summary"]["buckets_with_info"].add(name)
                
        except Exception as e:
            logger.exception("audit_bucket failed for %s", name)
            results["buckets"][name] = {"_error": str(e)}

    results["summary"]["critical"] = len(results["summary"]["buckets_with_critical"])
    results["summary"]["warning"] = len(results["summary"]["buckets_with_warning"])
    results["summary"]["info"] = len(results["summary"]["buckets_with_info"])
    
    results["summary"].pop("buckets_with_critical")
    results["summary"].pop("buckets_with_warning")
    results["summary"].pop("buckets_with_info")

    return results
_CACHED_SCAN_RESULTS = None


def get_s3_audit_summary():
    global _CACHED_SCAN_RESULTS
    
    if _CACHED_SCAN_RESULTS is None:
        logger.info("Running fresh S3 audit scan...")
        _CACHED_SCAN_RESULTS = scan_all_buckets_detailed(deep_object_check=False)
    
    result = _CACHED_SCAN_RESULTS
    
    summary = {
        "total_buckets": result["summary"]["total_buckets"],
        "critical_issues": result["summary"]["critical"],
        "warning_issues": result["summary"]["warning"],
        "info_issues": result["summary"]["info"],
        "buckets": []
    }
    
    # Add simplified bucket info
    for bucket_name, bucket_data in result["buckets"].items():
        if "_error" in bucket_data:
            summary["buckets"].append({
                "name": bucket_name,
                "error": bucket_data["_error"],
                "issue_count": 0,
                "critical_count": 0,
                "warning_count": 0
            })
        else:
            issues = bucket_data.get("issues", [])
            critical_count = sum(1 for i in issues if i.get("severity") == "CRITICAL")
            warning_count = sum(1 for i in issues if i.get("severity") == "WARNING")
            
            summary["buckets"].append({
                "name": bucket_name,
                "issue_count": len(issues),
                "critical_count": critical_count,
                "warning_count": warning_count,
                "encryption": bucket_data.get("encryption", {}).get("status", "UNKNOWN"),
                "logging": bucket_data.get("logging", {}).get("enabled", False),
                "versioning": bucket_data.get("versioning", {}).get("status", "Disabled")
            })
    
    return summary


def get_bucket_details(bucket_name):
    global _CACHED_SCAN_RESULTS
    
    if _CACHED_SCAN_RESULTS is None:
        logger.info("Running fresh S3 audit scan for bucket details...")
        _CACHED_SCAN_RESULTS = scan_all_buckets_detailed(deep_object_check=False)
    
    bucket_data = _CACHED_SCAN_RESULTS["buckets"].get(bucket_name)
    
    if bucket_data is None:
        return None
    
    return bucket_data


def refresh_scan_cache(deep_object_check=False, max_objects_per_bucket=50):

    global _CACHED_SCAN_RESULTS
    logger.info("Refreshing S3 audit scan cache...")
    _CACHED_SCAN_RESULTS = scan_all_buckets_detailed(
        deep_object_check=deep_object_check,
        max_objects_per_bucket=max_objects_per_bucket
    )
    return _CACHED_SCAN_RESULTS