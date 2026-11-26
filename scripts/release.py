#!/usr/bin/env python3
"""Standalone, offline builder for signed Universal EMS profile releases.

Run this from the root of the dedicated universal-ems-profiles repository.
Only reviewed read-only JSON is allowed into releases; signing key never
belongs in a repository or release artifact.
"""
import argparse
import base64
import json
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def validate_http_profile(profile: dict, identifier: str) -> None:
    """Restricted read-only go-e HTTP v2 schema. No executable mappings."""
    required = {"schema_version", "id", "version", "name", "manufacturer",
                "family", "category", "protocol", "read_only",
                "compatibility", "description", "source", "endpoint", "fields"}
    if (set(profile) != required or profile["schema_version"] != 2
            or profile["id"] != identifier
            or profile["manufacturer"] != "go-e"
            or profile["category"] != "wallbox"
            or profile["protocol"] != "http_json"
            or profile["read_only"] is not True
            or profile["endpoint"] != "/api/status"
            or not re.fullmatch(r"\d+\.\d+\.\d+", str(profile["version"]))):
        raise SystemExit(f"Invalid HTTP profile: {identifier}")
    for key in ("name", "manufacturer", "family", "description", "compatibility", "source"):
        if not isinstance(profile[key], str) or not 1 <= len(profile[key]) <= 500:
            raise SystemExit(f"Invalid HTTP profile metadata: {identifier}")
    approved = {
        "wallbox_charging_power_w": ("nrg", 11, "W", 10, 0, 100000),
        "wallbox_total_energy_wh": ("eto", None, "Wh", 1, 0, 1e12),
        "wallbox_set_current_a": ("amp", None, "A", 1, 0, 80),
        "wallbox_vehicle_status_code": ("car", None, "", 1, 0, 5),
        "wallbox_charge_allowed": ("alw", None, "", 1, 0, 1),
    }
    fields = profile["fields"]
    if not isinstance(fields, list) or not 1 <= len(fields) <= len(approved):
        raise SystemExit(f"Invalid HTTP profile fields: {identifier}")
    seen = set()
    for field in fields:
        if not isinstance(field, dict) or set(field) != {
                "metric", "key", "index", "unit", "factor", "minimum", "maximum"}:
            raise SystemExit(f"Invalid HTTP field structure: {identifier}")
        metric = field["metric"]
        if metric not in approved or metric in seen:
            raise SystemExit(f"Unsupported HTTP metric: {identifier}")
        key, index, unit, factor, low, high = approved[metric]
        if (field["key"] != key or field["index"] != index
                or field["unit"] != unit or field["factor"] != factor
                or type(field["minimum"]) not in (int, float)
                or type(field["maximum"]) not in (int, float)
                or not low <= field["minimum"] <= field["maximum"] <= high):
            raise SystemExit(f"Unsafe HTTP mapping: {identifier}")
        seen.add(metric)
    if "wallbox_vehicle_status_code" not in seen:
        raise SystemExit(f"Missing vehicle status check: {identifier}")


def validate_shelly_profile(profile: dict, identifier: str) -> None:
    """Validate only published, audited TopAC read-only field mappings."""
    import math
    required = {"schema_version", "id", "version", "name", "manufacturer",
                "family", "category", "protocol", "read_only",
                "compatibility", "description", "source", "fields"}
    if (set(profile) != required or type(profile["schema_version"]) is not int
            or profile["schema_version"] != 3 or profile["id"] != identifier
            or profile["manufacturer"] != "Shelly/TopAC"
            or profile["category"] != "wallbox"
            or profile["protocol"] != "shelly_rpc"
            or profile["read_only"] is not True
            or not re.fullmatch(r"\d+\.\d+\.\d+", str(profile["version"]))):
        raise SystemExit(f"Invalid Shelly profile: {identifier}")
    for key in ("name", "manufacturer", "family", "description", "compatibility", "source"):
        if not isinstance(profile[key], str) or not 1 <= len(profile[key]) <= 500:
            raise SystemExit(f"Invalid Shelly profile metadata: {identifier}")
    allowed = {
        "wallbox_charging_power_w": ("phase_info", "value.total_power", "W", 1000, 0, 30000),
        "wallbox_total_energy_wh": ("phase_info", "value.total_act_energy", "Wh", 1000, 0, 1e12),
        "wallbox_session_energy_wh": ("energy_charge", "value", "Wh", 1000, 0, 1e9),
        "wallbox_set_current_a": ("current_limit", "value", "A", 1, 0, 32),
        "wallbox_charge_current_a": ("phase_info", "value.total_current", "A", 1, 0, 100),
    }
    for phase in ("a", "b", "c"):
        for label, unit, bound in (("voltage", "V", 300), ("current", "A", 32), ("power", "W", 12000)):
            metric = f"wallbox_phase_{phase}_{label}_{unit.lower()}"
            allowed[metric] = ("phase_info", f"value.phase_{phase}.{label}", unit, 1000 if label == "power" else 1, 0, bound)
    fields = profile["fields"]
    if not isinstance(fields, list) or not 1 <= len(fields) <= len(allowed):
        raise SystemExit(f"Invalid Shelly fields: {identifier}")
    seen = set()
    for field in fields:
        if not isinstance(field, dict) or set(field) != {
                "metric", "role", "path", "unit", "factor", "minimum", "maximum"}:
            raise SystemExit(f"Invalid Shelly field: {identifier}")
        metric = field["metric"]
        if metric not in allowed or metric in seen:
            raise SystemExit(f"Unapproved Shelly metric: {identifier}")
        role, path, unit, factor, low, high = allowed[metric]
        if ((field["role"], field["path"], field["unit"], field["factor"])
                != (role, path, unit, factor)
                or type(field["minimum"]) not in (int, float)
                or type(field["maximum"]) not in (int, float)
                or not math.isfinite(field["minimum"])
                or not math.isfinite(field["maximum"])
                or not low <= field["minimum"] <= field["maximum"] <= high):
            raise SystemExit(f"Unsafe Shelly metric definition: {identifier}")
        seen.add(metric)
    if "wallbox_charging_power_w" not in seen:
        raise SystemExit(f"Missing Shelly charger power: {identifier}")


def build(version: str) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit("Version must be semantic version x.y.z")
    manifest = json.loads(Path("catalog.json").read_text(encoding="utf-8"))
    if (manifest.get("schema_version") != 1 or manifest.get("catalog_version") != version
            or not isinstance(manifest.get("profiles"), list)
            or not manifest["profiles"] or len(set(manifest["profiles"])) != len(manifest["profiles"])):
        raise SystemExit("Invalid or mismatched catalog version")
    profiles = {}
    for identifier in manifest["profiles"]:
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", identifier):
            raise SystemExit("Invalid profile identifier")
        path = Path("profiles") / (identifier + ".json")
        if not path.is_file() or path.stat().st_size > 64_000:
            raise SystemExit(f"Missing/oversized profile: {identifier}")
        profile = json.loads(path.read_text(encoding="utf-8"))
        if profile.get("schema_version") == 3:
            validate_shelly_profile(profile, identifier)
            profiles[identifier] = profile
            continue
        if profile.get("schema_version") == 2:
            validate_http_profile(profile, identifier)
            profiles[identifier] = profile
            continue
        if (profile.get("id") != identifier
                or profile.get("schema_version") != 1
                or profile.get("read_only") is not True
                or profile.get("protocol") != "modbus_tcp"
                or not re.fullmatch(r"\d+\.\d+\.\d+", str(profile.get("version", "")))
                or not isinstance(profile.get("registers"), list)
                or not 1 <= len(profile["registers"]) <= 64):
            raise SystemExit(f"Invalid read-only device profile: {identifier}")
        used, keys = set(), set()
        for r in profile["registers"]:
            if not isinstance(r, dict):
                raise SystemExit("Register must be a JSON object")
            kind = r.get("kind")
            required_words = {"uint16": 1, "float32_swapped": 2}.get(kind)
            if (required_words is None or type(r.get("words")) is not int
                    or r["words"] != required_words
                    or type(r.get("address")) is not int
                    or r["address"] < 0
                    or r["address"] + r["words"] > 65536
                    or not isinstance(r.get("metric"), str)
                    or not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", r["metric"])
                    or r["metric"] in keys):
                raise SystemExit(f"Invalid register in {identifier}")
            keys.add(r["metric"])
            location = set(range(r["address"], r["address"] + r["words"]))
            if used & location:
                raise SystemExit(f"Overlapping registers in {identifier}")
            used |= location
        profiles[identifier] = profile

    payload = {"format": 1, "catalog_version": version, "profiles": profiles}
    bundle = (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    if len(bundle) > 512_000:
        raise SystemExit("Bundle exceeds size limit")
    key_b64 = os.getenv("PROFILE_SIGNING_KEY_B64", "")
    try:
        raw = base64.b64decode(key_b64, validate=True)
        if len(raw) != 32:
            raise ValueError()
        private = Ed25519PrivateKey.from_private_bytes(raw)
    except Exception:
        raise SystemExit("Missing/invalid PROFILE_SIGNING_KEY_B64 GitHub Actions secret") from None
    destination = Path("dist")
    destination.mkdir(exist_ok=True)
    (destination / "bundle.json").write_bytes(bundle)
    (destination / "bundle.sig").write_text(
        base64.b64encode(private.sign(bundle)).decode("ascii") + "\n", encoding="ascii")
    print("Signed profiles-v" + version + " (" + str(len(profiles)) + " profiles)")


def keygen() -> None:
    private = Ed25519PrivateKey.generate()
    secret = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    directory = Path(".keys")
    directory.mkdir(exist_ok=True, mode=0o700)
    secret_path = directory / "signing-key.b64"
    with secret_path.open("x", encoding="ascii") as fd:
        os.chmod(secret_path, 0o600)
        fd.write(base64.b64encode(secret).decode("ascii") + "\n")
    (directory / "public-key.b64").write_text(
        base64.b64encode(public).decode("ascii") + "\n", encoding="ascii")
    print("Private key created in .keys/signing-key.b64. Store it in GitHub Actions secret PROFILE_SIGNING_KEY_B64.")
    print("Public key in .keys/public-key.b64 must be pinned in Universal EMS UEM_PROFILE_PUBLIC_KEY_B64.")
    print("Never commit or publish the private signing key.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["keygen", "build"])
    parser.add_argument("--version")
    args = parser.parse_args()
    if args.operation == "keygen":
        keygen()
    elif args.version:
        build(args.version)
    else:
        parser.error("--version is required for build")
