
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import tempfile
from pathlib import Path

ENGINE_RESULTS = {
    "summary": {},
    "roles": [],
    "findings": [],
    "endpoints": []
}

app = FastAPI(title="Authorization Intelligence Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def process_burp_xml(xml_path: str):
    try:
        from app.parsers.burp_xml_parser import parse_burp_xml
        from app.normalization.normalizer import normalize_traffic

        raw_items = parse_burp_xml(xml_path)
        result = normalize_traffic(raw_items)

        endpoints = []
        for tx in result.transactions:
            endpoints.append({
                "method": getattr(tx.request, "method", ""),
                "path": getattr(tx.request, "path", ""),
                "host": getattr(tx.request, "host", ""),
            })

        roles = []
        role_summary = result.role_mapper.get_summary()

        for role_name, role_data in role_summary.get("roles", {}).items():
            roles.append({
                "role": role_name,
                "tier": role_data.get("tier", 0),
                "scope": "unknown",
                "endpoints": role_data.get("endpoint_count", 0),
            })

        findings = []
        for role in roles:
            if "admin" in role["role"].lower():
                findings.append({
                    "severity": "Medium",
                    "type": "Privileged Role Detected",
                    "endpoint": "Role Intelligence",
                    "originalRole": role["role"],
                    "replayRole": "lower_privilege_role",
                    "similarity": "N/A"
                })

        ENGINE_RESULTS["summary"] = {
            "requests": len(raw_items),
            "api_candidates": len(result.transactions),
            "resource_ids": result.unique_resource_ids,
            "roles": len(roles),
            "jwt_tokens": result.jwt_tokens_found,
            "tenant_params": result.tenant_params_found,
            "capabilities": result.capabilities_mapped,
            "findings": len(findings)
        }

        ENGINE_RESULTS["roles"] = roles
        ENGINE_RESULTS["endpoints"] = endpoints
        ENGINE_RESULTS["findings"] = findings

        return {
            "success": True,
            "summary": ENGINE_RESULTS["summary"]
        }

    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/summary")
def summary():
    return ENGINE_RESULTS["summary"]

@app.get("/roles")
def roles():
    return ENGINE_RESULTS["roles"]

@app.get("/findings")
def findings():
    return ENGINE_RESULTS["findings"]

@app.get("/endpoints")
def endpoints():
    return ENGINE_RESULTS["endpoints"]

@app.get("/debug")
def debug():
    return ENGINE_RESULTS

@app.post("/upload")
async def upload_burp(file: UploadFile = File(...)):
    suffix = Path(file.filename).suffix

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        contents = await file.read()
        tmp.write(contents)
        tmp_path = tmp.name

    return process_burp_xml(tmp_path)
