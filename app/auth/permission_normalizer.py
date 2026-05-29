from __future__ import annotations
import re
from collections import defaultdict

ACTION_WORDS={"create","view","modify","delete","enabledisabledelete","all"}
RESOURCE_MAP={
"systemuser":"manage_users",
"user":"manage_users",
"portalinstitute":"manage_institutes",
"institute":"manage_institutes",
"tenant":"manage_tenants",
"report":"global_reporting",
"dashboard":"global_reporting",
"billing":"manage_billing",
}

def normalize_permissions(permissions:list[str])->dict:
    grouped=defaultdict(set)
    capabilities=set()

    for perm in permissions:
        clean=perm.lower().replace("prm_1_","")
        parts=clean.split("_")
        action=parts[-1]
        resource="_".join(parts[:-1]).replace("_","")

        grouped[resource].add(action)

        for k,v in RESOURCE_MAP.items():
            if k in resource:
                capabilities.add(v)

    return {
        "resources":{
            k:sorted(list(v)) for k,v in grouped.items()
        },
        "capabilities":sorted(list(capabilities))
    }
