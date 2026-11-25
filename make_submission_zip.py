"""
make_submission_zip.py - Build the submission ZIP (standard library only).

    python make_submission_zip.py

Creates ../secureTeam_SecureIoT-Sim.zip (next to the project folder) containing the
source code, README, requirements.txt, docs/ and results/ (sample outputs),
and leaving out what the brief forbids: virtual environments and caches.
The runtime folder data/ (databases, keystore, master key) is also left out.
"""

import os
import zipfile

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_NAME = "secureTeam_SecureIoT-Sim"     # GroupName_ProjectName, as the brief requires
ZIP_PATH = os.path.join(os.path.dirname(PROJECT_DIR), PROJECT_NAME + ".zip")
# deliverables/ (report + slides) is uploaded separately, so it is not put in the code ZIP.
SKIP_DIRS = {"venv", ".venv", "env", "__pycache__", "data", ".git", ".idea", ".vscode", "deliverables"}
SKIP_SUFFIXES = (".pyc", ".pyo", ".zip")


def files_to_include():
    """Yield (absolute path, path inside the zip) for every file that belongs in the ZIP."""
    for folder, dirs, files in os.walk(PROJECT_DIR):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name.endswith(SKIP_SUFFIXES):
                continue
            full = os.path.join(folder, name)
            inside = os.path.join(PROJECT_NAME, os.path.relpath(full, PROJECT_DIR))
            yield full, inside


def main():
    """Write the ZIP and print a short summary."""
    count = 0
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as archive:
        for full, inside in files_to_include():
            archive.write(full, inside)
            count += 1
    size_kb = os.path.getsize(ZIP_PATH) / 1024
    print(f"wrote {ZIP_PATH}  ({count} files, {size_kb:.0f} KB)")


if __name__ == "__main__":
    main()
