# Evidence Seal

Evidence Seal is an offline command-line tool for checking the integrity of collected files. Use it after acquisition to record a SHA-256 baseline, then verify a working copy before a handoff or analysis. It reads file contents and writes a JSON manifest outside the evidence directory.

## Quick start

Requires Python 3.9 or later on macOS or Linux. No third-party packages are required.

```sh
git clone https://github.com/gqnxx/evidence-seal.git
cd evidence-seal

# Create a synthetic evidence set.
mkdir -p demo-evidence
echo 'Synthetic case note' > demo-evidence/note.txt

python3 evidence_seal.py snapshot demo-evidence demo-manifest.json
python3 evidence_seal.py verify demo-evidence demo-manifest.json
```

The manifest records each file's relative path, byte count, and SHA-256 digest. Because the paths are relative, you can verify a copy in a different location. Snapshot refuses to overwrite an existing manifest.

```sh
echo 'A later edit' >> demo-evidence/note.txt
python3 evidence_seal.py verify demo-evidence demo-manifest.json
```

```text
CHANGED "note.txt"
Mismatch: 0 added, 0 missing, 1 changed.
```

| Exit code | Meaning |
| --- | --- |
| `0` | Manifest created or every file matched. |
| `1` | Verification found added, missing, or changed files. |
| `2` | Invalid arguments, malformed manifest, unsupported file type, or an I/O error. |

## Forensic scope

- Use a stable collection. Reading may update filesystem access times, so use a read-only mount when access times matter. Changes during an individual file read can trigger an error. The directory walk is not a point-in-time filesystem snapshot.
- Symbolic links and non-regular files cause the operation to fail. Empty directories, permissions, ownership, timestamps, and extended attributes are outside the manifest's scope.
- Keep the original manifest in a trusted, access-controlled location. Verification depends on that baseline. The manifest is unsigned and contains filenames, so handle it as case data.

## Tests

```sh
python3 -m unittest discover -s tests -v
```
