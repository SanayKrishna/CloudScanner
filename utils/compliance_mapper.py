# utils/compliance_mapper.py
"""
Compliance mapping helper.

Provide a single place to maintain mappings from internal issue IDs to
compliance references (CIS, NIST, ISO, etc.), short descriptions and remediation hints.

Expose:
- COMPLIANCE_MAP: dict mapping issue_id -> metadata
- get_compliance(issue_id): returns metadata dict or a safe default
"""

COMPLIANCE_MAP = {
    "public_bucket_policy": {
        "compliance": ["CIS 2.1.1"],
        "title": "Public bucket policy allows anonymous read",
        "description": "Bucket policy allows public access to objects (Principal=* or equivalent).",
        "remediation": "Remove public principals or restrict actions/resources in the bucket policy. Prefer least privilege."
    },
    "public_acl": {
        "compliance": ["CIS 2.1.4"],
        "title": "Bucket ACL grants public access",
        "description": "Bucket ACL contains grants to AllUsers or AuthenticatedUsers.",
        "remediation": "Remove public ACL grants; use bucket policies and keep 'Block Public Access' enabled."
    },
    "object_public_acl": {
        "compliance": ["CIS 2.1.5"],
        "title": "Object-level public ACL found",
        "description": "One or more objects in the bucket have public ACLs.",
        "remediation": "Remove public ACLs from objects and enforce bucket-level policy instead."
    },
    "encryption_missing": {
        "compliance": ["CIS 2.1.1"],
        "title": "Default encryption missing",
        "description": "Bucket has no default server-side encryption configured.",
        "remediation": "Enable default SSE (SSE-S3 or SSE-KMS) for the bucket to protect data at rest."
    },
    "logging_disabled": {
        "compliance": ["CIS 2.2.1"],
        "title": "Access logging disabled",
        "description": "Server access logging is not enabled for the bucket.",
        "remediation": "Enable server access logging to a dedicated logging bucket for auditability."
    },
    "versioning_disabled": {
        "compliance": ["CIS 2.3.1"],
        "title": "Versioning disabled",
        "description": "Bucket versioning is not enabled.",
        "remediation": "Enable versioning to allow recovery from accidental deletes or overwrites."
    },
    "replication_disabled": {
        "compliance": ["ISO 27001"],
        "title": "Replication (CRR) not configured",
        "description": "Cross-region replication is not configured for this bucket.",
        "remediation": "Consider enabling CRR for critical data to satisfy DR/availability requirements."
    },
    "block_public_access": {
        "compliance": ["CIS 2.1.2"],
        "title": "Block Public Access not strict",
        "description": "Bucket account or bucket-level Block Public Access settings are not fully enabled.",
        "remediation": "Enable Block Public Access at account or bucket level for production buckets."
    }
}


def get_compliance(issue_id):
    """
    Return compliance metadata dict for the given issue_id.
    If not found, return a default structure.
    """
    default = {
        "compliance": [],
        "title": issue_id,
        "description": "",
        "remediation": ""
    }
    return COMPLIANCE_MAP.get(issue_id, default)
