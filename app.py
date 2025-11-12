from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from utils.s3_audit import get_s3_audit_summary, get_bucket_details, refresh_scan_cache
from utils.cloudtrail_monitor import get_threat_findings, get_bucket_threat_activity
from utils.mock_threat_generator import get_mock_threat_findings
from report import generate_pdf_report
import datetime
import os
import boto3
from botocore.exceptions import ClientError

# Create required directories if they don't exist
os.makedirs("static", exist_ok=True)
os.makedirs("static/css", exist_ok=True)
os.makedirs("static/js", exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs("utils", exist_ok=True)
os.makedirs("outputs", exist_ok=True)

app = FastAPI(title="S3 Security Dashboard")

# Demo mode configuration
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"
DEMO_SCENARIO = os.getenv("DEMO_SCENARIO", "mixed")

# Static & templates setup
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Render the main S3 dashboard."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/threats", response_class=HTMLResponse)
async def serve_threat_dashboard(request: Request):
    """Render the threat detection dashboard."""
    return templates.TemplateResponse("threat_dashboard.html", {"request": request})


@app.get("/scan")
async def scan_endpoint():
    """
    Main scan endpoint that the frontend calls.
    Returns data in the format expected by dashboard.html
    """
    try:
        # Get the audit summary
        summary = get_s3_audit_summary()
        
        # Transform data to match frontend expectations
        response_data = {
            "success": True,
            "data": {
                "generated_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_buckets": summary.get("total_buckets", 0),
                "public_count": summary.get("critical_issues", 0),
                "versioning_count": summary.get("warning_issues", 0),
                "unencrypted_count": summary.get("info_issues", 0),
                "public_buckets": [],
                "versioning_disabled": [],
                "unencrypted_buckets": []
            }
        }
        
        # Categorize buckets based on their issues
        for bucket in summary.get("buckets", []):
            bucket_name = bucket.get("name")
            
            # Check if bucket has critical issues (public)
            if bucket.get("critical_count", 0) > 0:
                response_data["data"]["public_buckets"].append(bucket_name)
            
            # Check if versioning is disabled
            if bucket.get("versioning") == "Disabled":
                response_data["data"]["versioning_disabled"].append(bucket_name)
            
            # Check if encryption is missing
            encryption = bucket.get("encryption", "UNKNOWN")
            if encryption in ["NONE", "UNKNOWN"]:
                response_data["data"]["unencrypted_buckets"].append(bucket_name)
        
        return JSONResponse(content=response_data)
        
    except Exception as e:
        print(f"Error in /scan endpoint: {str(e)}")
        import traceback
        traceback.print_exc()
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.get("/bucket-details/{bucket_name}")
async def fetch_bucket_details_for_frontend(bucket_name: str):
    """
    Get detailed bucket information in the format expected by the frontend.
    """
    try:
        # Get detailed bucket info
        details = get_bucket_details(bucket_name)
        
        if not details:
            return JSONResponse(content={
                "success": False,
                "error": "Bucket not found"
            }, status_code=404)
        
        # Get additional details from boto3
        s3 = boto3.client('s3')
        
        # Get public access block configuration
        try:
            public_block = s3.get_public_access_block(Bucket=bucket_name)
            config = public_block.get('PublicAccessBlockConfiguration', {})
            public_access_block = {
                "block_public_acls": config.get('BlockPublicAcls', False),
                "ignore_public_acls": config.get('IgnorePublicAcls', False),
                "block_public_policy": config.get('BlockPublicPolicy', False),
                "restrict_public_buckets": config.get('RestrictPublicBuckets', False)
            }
        except ClientError:
            public_access_block = {
                "block_public_acls": False,
                "ignore_public_acls": False,
                "block_public_policy": False,
                "restrict_public_buckets": False
            }
        
        # Get objects
        objects_list = []
        total_size = 0
        total_objects = 0
        
        try:
            paginator = s3.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=bucket_name, MaxKeys=100)
            
            for page in page_iterator:
                for obj in page.get('Contents', [])[:100]:  # Limit to 100 objects
                    total_objects += 1
                    size = obj.get('Size', 0)
                    total_size += size
                    
                    objects_list.append({
                        "key": obj.get('Key', ''),
                        "size": size,
                        "last_modified": obj.get('LastModified').strftime('%Y-%m-%d %H:%M:%S') if obj.get('LastModified') else 'N/A',
                        "is_public": False,  # Would need to check ACL
                        "encryption": details.get("encryption", {}).get("status", "None")
                    })
                    
                    if len(objects_list) >= 100:
                        break
                if len(objects_list) >= 100:
                    break
                    
        except ClientError as e:
            print(f"Error listing objects: {e}")
        
        # Format response
        response_data = {
            "success": True,
            "data": {
                "bucket_name": bucket_name,
                "versioning_status": details.get("versioning", {}).get("status", "Disabled"),
                "encryption_status": details.get("encryption", {}).get("status", "None"),
                "total_objects": total_objects,
                "total_size": total_size,
                "has_more": total_objects > 100,
                "public_access_block": public_access_block,
                "objects": objects_list
            }
        }
        
        return JSONResponse(content=response_data)
        
    except Exception as e:
        print(f"Error fetching bucket details: {str(e)}")
        import traceback
        traceback.print_exc()
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.get("/api/summary")
async def fetch_audit_summary():
    """Return overall S3 audit summary."""
    try:
        summary = get_s3_audit_summary()
        return JSONResponse(content=summary)
    except Exception as e:
        print(f"Error in /api/summary: {str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/api/bucket/{bucket_name}")
async def fetch_bucket_details(bucket_name: str):
    """Return detailed info for one specific bucket."""
    try:
        details = get_bucket_details(bucket_name)
        if not details:
            return JSONResponse(content={"error": "Bucket not found"}, status_code=404)
        return JSONResponse(content=details)
    except Exception as e:
        print(f"Error in /api/bucket/{bucket_name}: {str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/api/refresh")
async def refresh_scan():
    """Re-scan all S3 buckets and return updated summary."""
    try:
        refresh_scan_cache()
        summary = get_s3_audit_summary()
        return JSONResponse(content={
            "status": "success",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "data": summary
        })
    except Exception as e:
        print(f"Error in /api/refresh: {str(e)}")
        return JSONResponse(content={
            "status": "error",
            "error": str(e)
        }, status_code=500)


@app.get("/api/report/pdf")
async def download_report():
    """Generate and download the latest PDF security report."""
    try:
        output_path = generate_pdf_report()
        if not os.path.exists(output_path):
            return JSONResponse(content={"error": "Report generation failed"}, status_code=500)
        return FileResponse(
            output_path,
            media_type="application/pdf",
            filename="S3_Security_Report.pdf"
        )
    except Exception as e:
        print(f"Error generating PDF report: {str(e)}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ============ THREAT DETECTION ENDPOINTS ============

@app.get("/api/threats")
async def get_threats(hours: int = 24, demo: str = None):
    """
    Get CloudTrail-based threat detection findings
    Query params: 
    - hours (default: 24) - how far back to analyze
    - demo (optional) - use mock data (values: clean, mixed, critical, mass_deletion, policy_change, data_exfil)
    """
    try:
        # Check if demo mode is requested
        use_demo = demo is not None or DEMO_MODE
        demo_scenario = demo if demo else DEMO_SCENARIO
        
        if use_demo:
            print(f"🎭 Demo mode activated: {demo_scenario}")
            findings = get_mock_threat_findings(scenario=demo_scenario, hours=hours)
        else:
            # Real CloudTrail analysis
            findings = get_threat_findings(hours=hours, force_refresh=False)
        
        return JSONResponse(content={
            "success": True,
            "data": findings,
            "demo_mode": use_demo
        })
        
    except Exception as e:
        print(f"Error in /api/threats: {str(e)}")
        import traceback
        traceback.print_exc()
        return JSONResponse(content={
            "success": False,
            "error": str(e),
            "data": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "summary": {
                    "total_events": 0,
                    "suspicious_events": 0,
                    "critical_findings": 0,
                    "high_findings": 0,
                    "medium_findings": 0
                }
            }
        }, status_code=500)


@app.get("/api/threats/refresh")
async def refresh_threats(hours: int = 24, demo: str = None):
    """
    Force refresh threat detection analysis
    Query params:
    - hours (default: 24) - how far back to analyze
    - demo (optional) - use mock data for demo
    """
    try:
        use_demo = demo is not None or DEMO_MODE
        demo_scenario = demo if demo else DEMO_SCENARIO
        
        if use_demo:
            print(f"🎭 Demo mode refresh: {demo_scenario}")
            findings = get_mock_threat_findings(scenario=demo_scenario, hours=hours)
        else:
            # Real CloudTrail analysis with force refresh
            findings = get_threat_findings(hours=hours, force_refresh=True)
        
        return JSONResponse(content={
            "success": True,
            "data": findings,
            "message": "Threat analysis refreshed successfully",
            "demo_mode": use_demo
        })
        
    except Exception as e:
        print(f"Error in /api/threats/refresh: {str(e)}")
        import traceback
        traceback.print_exc()
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.get("/api/threats/bucket/{bucket_name}")
async def get_bucket_threats(bucket_name: str, hours: int = 24):
    """
    Get threat activity for a specific bucket
    Query param: hours (default: 24) - how far back to analyze
    """
    try:
        activity = get_bucket_threat_activity(bucket_name, hours=hours)
        
        return JSONResponse(content={
            "success": True,
            "data": activity
        })
        
    except Exception as e:
        print(f"Error in /api/threats/bucket/{bucket_name}: {str(e)}")
        import traceback
        traceback.print_exc()
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.get("/api/threats/summary")
async def get_threat_summary(demo: str = None):
    """Get a quick summary of current threats"""
    try:
        use_demo = demo is not None or DEMO_MODE
        demo_scenario = demo if demo else DEMO_SCENARIO
        
        if use_demo:
            findings = get_mock_threat_findings(scenario=demo_scenario, hours=24)
        else:
            findings = get_threat_findings(hours=24, force_refresh=False)
        
        summary = {
            "total_suspicious_events": findings["summary"].get("suspicious_events", 0),
            "critical_count": len(findings.get("critical", [])),
            "high_count": len(findings.get("high", [])),
            "medium_count": len(findings.get("medium", [])),
            "scan_period": findings["summary"].get("scan_period_hours", 24),
            "last_updated": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "demo_mode": use_demo
        }
        
        return JSONResponse(content={
            "success": True,
            "data": summary
        })
        
    except Exception as e:
        print(f"Error in /api/threats/summary: {str(e)}")
        # Return safe default on error
        return JSONResponse(content={
            "success": True,
            "data": {
                "total_suspicious_events": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "scan_period": 24,
                "last_updated": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "demo_mode": False
            }
        })


@app.get("/api/threats/demo/{scenario}")
async def get_demo_threats(scenario: str, hours: int = 24):
    """
    Get specific demo threat scenario
    Scenarios: clean, mixed, critical, mass_deletion, policy_change, data_exfil
    """
    valid_scenarios = ["clean", "mixed", "critical", "mass_deletion", "policy_change", "data_exfil"]
    
    if scenario not in valid_scenarios:
        return JSONResponse(content={
            "success": False,
            "error": f"Invalid scenario. Must be one of: {', '.join(valid_scenarios)}"
        }, status_code=400)
    
    try:
        findings = get_mock_threat_findings(scenario=scenario, hours=hours)
        
        return JSONResponse(content={
            "success": True,
            "data": findings,
            "demo_mode": True,
            "scenario": scenario
        })
        
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return JSONResponse(content={
        "status": "healthy",
        "timestamp": datetime.datetime.utcnow().isoformat()
    })


if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting S3 Security Dashboard...")
    print("📊 Dashboard: http://localhost:8000")
    print("🚨 Threats: http://localhost:8000/threats")
    print(f"🎭 Demo Mode: {'ENABLED' if DEMO_MODE else 'DISABLED'}")
    if DEMO_MODE:
        print(f"📋 Demo Scenario: {DEMO_SCENARIO}")
    uvicorn.run(app, host="0.0.0.0", port=8000)