# Universal EMS – independently published profile library

This is the standalone public profile catalog for Universal EMS. Signed GitHub Releases are distributed to gateways after maintainers review and publish them.

## One-time signing setup

1. In a local clone of the new repository, install Python and `cryptography`, then execute `python scripts/release.py keygen`. This creates a private key in `.keys/signing-key.b64` and a public verification key in `.keys/public-key.b64`. **Keep the private key out of Git and backups exposed to customers.**
2. In GitHub repository **Settings → Secrets and variables → Actions**, create a repository secret `PROFILE_SIGNING_KEY_B64` containing the private key's base64 text. Save the public key for the customer gateway's `.env` (`UEM_PROFILE_PUBLIC_KEY_B64`).
3. Commit and push the reviewed profile JSON and the workflow. Run GitHub Actions **Publish signed device profiles** with version `1.0.0`. The workflow signs exactly the bytes of `bundle.json` and publishes `bundle.json` and `bundle.sig` as assets under the release tag `profiles-v1.0.0`.

The signer rejects write access, overlapping registers, invalid IDs, unknown wire decoders and malformed version tags. Universal EMS independently validates the signature against a pinned Ed25519 public key, parses each profile using its own stricter schema, and requires manual installation.

## Next versions

For a new supported device, add its reviewed `profiles/<id>.json`, list its ID in `catalog.json`, increase `catalog_version`, add tests or hardware evidence, then publish a new signed release. Each profile carries its own independent `version`. An update changing a profile used by an installed device is **blocked** until an explicit migration process is implemented; no register map is silently replaced.

This pilot supports read-only Modbus TCP profiles only. SunSpec's self-describing standard remains handled separately by its own generic adapter.

## Security and availability

- Only reviewed releases should be signed. Branch protections and workflow secret access must be restricted to maintainers.
- Do not share the Ed25519 signing key. The public key alone does not permit publishing trusted bundles.
- Do not rely on SHA-256 alone as proof of trust; the gateway verifies an Ed25519 signature over the exact release bytes.
- GitHub public releases work without credentials. Private releases are not supported by the customer updater in this first version.
- Gateways operate offline with the bundled/previously installed profiles. Checking and installing updates is always an explicit action.
- The implementation does not yet perform general model discovery, cloud credential provisioning, code-signing key rotation, or per-device migration.
