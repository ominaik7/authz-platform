"""CLI entry point for the Authorization Testing Platform — Phase 1.5: Authorization Intelligence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .parsers.burp_xml_parser import parse_burp_xml
from .normalization.normalizer import normalize_traffic
from .utils.logging import setup_logging


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Authorization Testing Platform — Authorization Intelligence Layer",
    )
    parser.add_argument(
        "--burp",
        required=True,
        help="Path to Burp Suite XML export file",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output JSON file path (default: stdout)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--include-filtered",
        action="store_true",
        help="Include filtered-out items in output (for debugging)",
    )

    args = parser.parse_args()

    # Setup logging
    log_level = 10 if args.verbose else 20  # DEBUG=10, INFO=20
    setup_logging(log_level)

    # Validate input file
    burp_path = Path(args.burp)
    if not burp_path.exists():
        print(f"[-] File not found: {args.burp}", file=sys.stderr)
        sys.exit(1)

    if not burp_path.is_file():
        print(f"[-] Not a file: {args.burp}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Loading XML: {args.burp}")

    # Step 1: Parse Burp XML
    raw_items = parse_burp_xml(str(burp_path))
    print(f"[+] Parsed {len(raw_items)} requests from XML")

    # Step 2: Normalize traffic (includes auth intelligence pipeline)
    result = normalize_traffic(raw_items)

    # Step 3: Print normalization summary
    print(f"[+] Filtered {result.filtered_count} static assets")
    if result.filtered_reasons:
        for reason, count in sorted(result.filtered_reasons.items()):
            print(f"    - {reason}: {count}")
    print(f"[+] Deduplicated {result.duplicate_count} duplicate requests")
    print(f"[+] Retained {len(result.transactions)} API candidates")
    print(f"[+] Extracted {result.unique_resource_ids} unique resource IDs")

    # Step 4: Print authorization intelligence summary
    print(f"\n{'='*60}")
    print("[+] Authorization Intelligence Summary")
    print(f"{'='*60}")
    print(f"    JWT tokens found:      {result.jwt_tokens_found}")
    print(f"    Tenant params found:   {result.tenant_params_found}")
    print(f"    Capabilities mapped:   {result.capabilities_mapped}")

    # Role hierarchy
    hierarchy_result = result.role_mapper.infer_hierarchy()
    role_hierarchy = hierarchy_result.get("hierarchy", [])
    role_details = hierarchy_result.get("roles", {})
    if role_hierarchy:
        print(f"\n[*] Inferred Role Hierarchy:")
        for level, role_name in enumerate(role_hierarchy, 1):
            tier = role_details.get(role_name, {}).get("privilege_tier", "?")
            print(f"    {level}. {role_name} (tier: {tier})")

    # Role coverage summary
    role_summary = result.role_mapper.get_summary()
    if role_summary["roles"]:
        print(f"\n[*] Role Coverage:")
        for role_name, role_data in role_summary["roles"].items():
            print(f"    {role_name}:")
            print(f"      - Endpoints accessed: {role_data['endpoint_count']}")
            print(f"      - Privilege tier: {role_data.get('privilege_tier', role_data.get('tier', 'unknown'))}")
            if role_data.get("capabilities"):
                print(f"      - Capabilities: {', '.join(role_data['capabilities'])}")
            if role_data.get("tenant_scope"):
                print(f"      - Tenant scope: {role_data['tenant_scope']}")

    # Authz graph summary
    graph_summary = result.authz_graph.get_summary()
    print(f"\n[*] Authorization Graph:")
    print(f"    Total endpoints:       {graph_summary['total_endpoints']}")
    print(f"    High-sensitivity:      {graph_summary['high_sensitivity_endpoints']}")
    print(f"    Admin-only endpoints:   {graph_summary['admin_only_endpoints']}")
    print(f"    Tenant-aware endpoints:{graph_summary['tenant_aware_endpoints']}")
    print(f"    Auth-required endpoints:{graph_summary['auth_required_endpoints']}")
    print(f"    Roles observed:        {graph_summary['total_roles']}")
    print(f"    Tenant boundaries:     {graph_summary['total_tenant_boundaries']}")
    print(f"    Capabilities:          {graph_summary['total_capabilities']}")
    print(f"    Auth signals:          {graph_summary['total_auth_signals']}")

    # Authz signals
    if graph_summary["auth_signals"]:
        print(f"\n[!] Authorization Signals Detected:")
        for signal in graph_summary["auth_signals"]:
            print(f"    [{signal['signal_type']}] {signal.get('endpoint_key', 'N/A')} → {signal.get('role', 'N/A')}")
            if signal.get("details"):
                for k, v in signal["details"].items():
                    print(f"        {k}: {v}")

    if result.decode_errors:
        print(f"\n[!] {result.decode_errors} decode errors encountered")

    # Step 5: Build structured output
    output_data = {
        "transactions": [t.model_dump() for t in result.transactions],
        "authorization_intelligence": {
            "role_hierarchy": [
                {"role": role_name, "privilege_tier": role_details.get(role_name, {}).get("privilege_tier", 0)}
                for role_name in role_hierarchy
            ],
            "role_coverage": role_summary,
            "authz_graph": graph_summary,
        },
        "statistics": {
            "total_parsed": result.total_parsed,
            "filtered_count": result.filtered_count,
            "filtered_reasons": result.filtered_reasons,
            "duplicate_count": result.duplicate_count,
            "retained_count": len(result.transactions),
            "api_candidates": result.api_candidates,
            "unique_resource_ids": result.unique_resource_ids,
            "jwt_tokens_found": result.jwt_tokens_found,
            "tenant_params_found": result.tenant_params_found,
            "capabilities_mapped": result.capabilities_mapped,
            "decode_errors": result.decode_errors,
        },
    }

    if args.output:
        output_path = Path(args.output)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, default=str)
        print(f"\n[+] Output written to {args.output}")
    else:
        print("\n[+] Structured Output:")
        print(json.dumps(output_data, indent=2, default=str))


if __name__ == "__main__":
    main()
