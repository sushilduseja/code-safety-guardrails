import argparse
import sys
import hashlib
from src.db import init_db, issue_key, connect

def main():
    parser = argparse.ArgumentParser(description="Manage API keys for Code Safety Guardrails")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # issue-key
    issue_parser = subparsers.add_parser("issue-key", help="Issue a new API key")
    issue_parser.add_argument("--tenant", required=True, help="Tenant ID")
    issue_parser.add_argument("--rpm", type=int, default=60, help="Requests per minute limit")

    # revoke-key
    revoke_parser = subparsers.add_parser("revoke-key", help="Revoke an API key")
    revoke_parser.add_argument("--tenant", required=True, help="Tenant ID")
    revoke_parser.add_argument("--key-hash", required=True, help="Hash of the API key to revoke")

    # list-keys
    list_parser = subparsers.add_parser("list-keys", help="List all API keys")

    args = parser.parse_args()

    init_db()

    if args.command == "issue-key":
        key = issue_key(args.tenant, args.rpm)
        print(f"Issued new key for {args.tenant}: {key}")
        print("Save this key now! It will never be shown again.")
    elif args.command == "revoke-key":
        with connect() as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET revoked_at=datetime('now') WHERE tenant_id=? AND key_hash=?",
                (args.tenant, args.key_hash)
            )
            if cursor.rowcount > 0:
                print(f"Revoked key {args.key_hash} for {args.tenant}")
            else:
                print(f"Key {args.key_hash} not found for tenant {args.tenant}")
    elif args.command == "list-keys":
        with connect() as conn:
            rows = conn.execute("SELECT key_hash, tenant_id, rpm_limit, created_at, revoked_at FROM api_keys").fetchall()
            print(f"{'Tenant ID':<20} | {'Key Hash':<64} | {'RPM':<5} | {'Created At':<20} | {'Revoked At'}")
            print("-" * 135)
            for row in rows:
                print(f"{row['tenant_id']:<20} | {row['key_hash']:<64} | {row['rpm_limit']:<5} | {row['created_at']:<20} | {row['revoked_at'] or ''}")

if __name__ == "__main__":
    main()
