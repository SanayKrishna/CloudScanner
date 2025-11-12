import boto3
from botocore.exceptions import ClientError

def scan_s3_buckets():
    s3 = boto3.client('s3')
    findings = {
        "public_buckets": [],
        "unencrypted_buckets": [],
        "versioning_disabled": []
    }

    try:
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            name = bucket["Name"]

            # --- Check 1: Public Access ---
            try:
                public_access = s3.get_public_access_block(Bucket=name)
                config = public_access["PublicAccessBlockConfiguration"]
                if not all(config.values()):  # any setting turned off
                    findings["public_buckets"].append(name)
            except ClientError:
                # If the bucket doesn't have a public access block set
                findings["public_buckets"].append(name)

            # --- Check 2: Encryption ---
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError:
                findings["unencrypted_buckets"].append(name)

            # --- Check 3: Versioning ---
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                findings["versioning_disabled"].append(name)

        return findings

    except ClientError as e:
        print(f"Error scanning buckets: {e}")
        return None


if __name__ == "__main__":
    print("🔍 Starting S3 Misconfiguration Scan...")
    from pprint import pprint
    results = scan_s3_buckets()
    pprint(results)
