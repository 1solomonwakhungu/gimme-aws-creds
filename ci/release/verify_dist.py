#!/usr/bin/env python3
"""Validate built gimme-aws-creds release artifacts and record or check their hashes.

This script inspects the wheel and sdist produced by the release build without
installing or executing them. It checks archive structure, metadata, declared
dependencies (including the urllib3 security floor), license notices, the wheel
RECORD, and, for release events, that the version matches the release tag.

Usage:
    verify_dist.py DIST_DIR --requirements requirements.txt [--expected-tag vX.Y.Z]
                   [--write-sums FILE | --check-sums FILE]

Exit status is 0 when every check passes and 1 otherwise. A JSON summary is
written to stdout; failures are written to stderr.
"""
import argparse
import base64
import csv
import hashlib
import io
import json
import re
import sys
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

PROJECT_NAME = "gimme-aws-creds"
IMPORT_PACKAGE = "gimme_aws_creds"
REQUIRED_NOTICES = ("LICENSE", "NOTICE")
SDIST_REQUIRED_FILES = ("PKG-INFO", "LICENSE", "NOTICE", "requirements.txt", "setup.py", "pyproject.toml")
MAX_ARTIFACT_BYTES = 20 * 1024 * 1024
MAX_MEMBER_BYTES = 10 * 1024 * 1024
MAX_MEMBERS = 2000

# GHSA-gm62-xv2j-4w53 (unbounded Content-Encoding chain) is fixed in urllib3 2.6.0;
# the project floor is 2.6.3. Releases must never allow an older urllib3.
URLLIB3_FLOOR = Version("2.6.3")
URLLIB3_FORBIDDEN_PROBES = ("1.26.20", "2.0.0", "2.5.0", "2.6.0", "2.6.2", "2.6.3rc1")
SUPPORTED_PYTHONS = ("3.10", "3.11", "3.12", "3.13", "3.14")
UNSUPPORTED_PYTHONS = ("3.9",)

SUMS_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._+-]+)$")


class VerificationError(Exception):
    """Raised when an artifact cannot be inspected safely."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_artifacts(dist_dir, failures):
    """Return (wheel, sdist) paths, requiring exactly one of each and nothing unexpected."""
    entries = sorted(p for p in dist_dir.iterdir() if p.name != "SHA256SUMS")
    wheels = [p for p in entries if p.name.endswith(".whl")]
    sdists = [p for p in entries if p.name.endswith(".tar.gz")]
    unexpected = [p.name for p in entries if p not in wheels and p not in sdists]
    if unexpected:
        failures.append(f"unexpected files in dist directory: {unexpected}")
    if len(wheels) != 1 or len(sdists) != 1:
        failures.append(f"expected exactly one wheel and one sdist, found {len(wheels)} wheel(s) and {len(sdists)} sdist(s)")
        return None, None
    for path in (wheels[0], sdists[0]):
        if path.is_symlink() or not path.is_file():
            failures.append(f"{path.name} is not a regular file")
            return None, None
        size = path.stat().st_size
        if size == 0 or size > MAX_ARTIFACT_BYTES:
            failures.append(f"{path.name} has implausible size {size} bytes")
            return None, None
    return wheels[0], sdists[0]


def safe_member_name(name):
    """Reject absolute paths, parent traversal, backslashes and empty components."""
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        return False
    parts = PurePosixPath(name).parts
    return all(part not in ("", "..") for part in parts) and not re.match(r"^[A-Za-z]:", name)


def parse_metadata(text):
    return Parser().parsestr(text)


def read_wheel(path, failures):
    """Inspect a wheel and return its parsed METADATA message."""
    with zipfile.ZipFile(path) as wheel:
        infos = wheel.infolist()
        if len(infos) > MAX_MEMBERS:
            raise VerificationError(f"{path.name} has too many members ({len(infos)})")
        names = []
        for info in infos:
            if not safe_member_name(info.filename):
                failures.append(f"wheel member has unsafe path: {info.filename!r}")
            if info.file_size > MAX_MEMBER_BYTES:
                failures.append(f"wheel member {info.filename} is too large ({info.file_size} bytes)")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                failures.append(f"wheel member {info.filename} is a symbolic link")
            names.append(info.filename)
        if len(set(names)) != len(names):
            failures.append("wheel contains duplicate member names")

        dist_infos = {n.split("/", 1)[0] for n in names if n.split("/", 1)[0].endswith(".dist-info")}
        if len(dist_infos) != 1:
            raise VerificationError(f"wheel must contain exactly one .dist-info directory, found {sorted(dist_infos)}")
        dist_info = dist_infos.pop()
        data_dir = dist_info[: -len(".dist-info")] + ".data"
        top_level = {n.split("/", 1)[0] for n in names}
        allowed = {IMPORT_PACKAGE, dist_info, data_dir}
        extra_top = sorted(top_level - allowed)
        if extra_top:
            failures.append(f"wheel installs unexpected top-level entries: {extra_top}")

        metadata = parse_metadata(wheel.read(f"{dist_info}/METADATA").decode("utf-8"))
        wheel_info = parse_metadata(wheel.read(f"{dist_info}/WHEEL").decode("utf-8"))
        if wheel_info.get("Root-Is-Purelib", "").strip().lower() != "true":
            failures.append("wheel is not marked Root-Is-Purelib: true")
        tags = wheel_info.get_all("Tag") or []
        if tags != ["py3-none-any"]:
            failures.append(f"wheel tags must be exactly ['py3-none-any'], found {tags}")

        for notice in REQUIRED_NOTICES:
            if f"{dist_info}/licenses/{notice}" not in names:
                failures.append(f"wheel is missing license notice {notice}")

        verify_record(wheel, dist_info, names, failures)
    return metadata


def verify_record(wheel, dist_info, names, failures):
    """Check that RECORD lists every member exactly once with a matching sha256."""
    record_name = f"{dist_info}/RECORD"
    rows = list(csv.reader(io.StringIO(wheel.read(record_name).decode("utf-8"))))
    recorded = {}
    for row in rows:
        if not row:
            continue
        if len(row) != 3:
            failures.append(f"malformed RECORD row: {row}")
            continue
        recorded[row[0]] = row[1]
    missing = sorted(set(names) - set(recorded))
    phantom = sorted(set(recorded) - set(names))
    if missing:
        failures.append(f"RECORD omits wheel members: {missing}")
    if phantom:
        failures.append(f"RECORD lists files absent from the wheel: {phantom}")
    for name, digest in recorded.items():
        if name == record_name or name not in names:
            continue
        if not digest.startswith("sha256="):
            failures.append(f"RECORD entry {name} lacks a sha256 digest")
            continue
        actual = base64.urlsafe_b64encode(hashlib.sha256(wheel.read(name)).digest()).rstrip(b"=").decode()
        if digest[len("sha256="):] != actual:
            failures.append(f"RECORD digest mismatch for {name}")


def read_sdist(path, failures):
    """Inspect an sdist and return (PKG-INFO message, requirements.txt text)."""
    with tarfile.open(path, mode="r:gz") as sdist:
        members = sdist.getmembers()
        if len(members) > MAX_MEMBERS:
            raise VerificationError(f"{path.name} has too many members ({len(members)})")
        roots = set()
        for member in members:
            if not safe_member_name(member.name):
                failures.append(f"sdist member has unsafe path: {member.name!r}")
            if not (member.isfile() or member.isdir()):
                failures.append(f"sdist member {member.name} is not a regular file or directory")
            if member.size > MAX_MEMBER_BYTES:
                failures.append(f"sdist member {member.name} is too large ({member.size} bytes)")
            roots.add(member.name.split("/", 1)[0])
        if len(roots) != 1:
            raise VerificationError(f"sdist must have a single root directory, found {sorted(roots)}")
        root = roots.pop()
        expected_root = path.name[: -len(".tar.gz")]
        if root != expected_root:
            failures.append(f"sdist root {root!r} does not match file name {expected_root!r}")

        def read_text(relative):
            member = sdist.getmember(f"{root}/{relative}")
            if not member.isfile():
                raise VerificationError(f"sdist {relative} is not a regular file")
            return sdist.extractfile(member).read().decode("utf-8")

        present = {m.name for m in members}
        for required in SDIST_REQUIRED_FILES:
            if f"{root}/{required}" not in present:
                failures.append(f"sdist is missing {required}")
        pkg_info = parse_metadata(read_text("PKG-INFO"))
        requirements = read_text("requirements.txt") if f"{root}/requirements.txt" in present else ""
    return pkg_info, requirements


def parse_requirement_lines(text):
    """Parse requirements.txt-style text into normalized requirement strings."""
    parsed = set()
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            raise VerificationError(f"unsupported requirements option in runtime requirements: {line}")
        parsed.add(str(Requirement(line)))
    return parsed


def runtime_requirements(metadata):
    """Return non-extra Requires-Dist entries as normalized strings."""
    result = set()
    for value in metadata.get_all("Requires-Dist") or []:
        requirement = Requirement(value)
        if requirement.marker is not None and "extra" in str(requirement.marker):
            continue
        result.add(str(requirement))
    return result


def check_urllib3_floor(requirements, failures):
    """Require a urllib3 constraint that excludes every version below URLLIB3_FLOOR."""
    matches = [Requirement(r) for r in requirements if canonicalize_name(Requirement(r).name) == "urllib3"]
    if len(matches) != 1:
        failures.append(f"expected exactly one unconditional urllib3 requirement, found {len(matches)}")
        return
    requirement = matches[0]
    if requirement.marker is not None:
        failures.append(f"urllib3 requirement must not be conditional: {requirement}")
    specifier = requirement.specifier
    lower_bounds = [
        Version(spec.version)
        for spec in specifier
        if spec.operator in (">=", ">", "==", "~=", "===") and not spec.version.endswith(".*")
    ]
    if not lower_bounds or max(lower_bounds) < URLLIB3_FLOOR:
        failures.append(f"urllib3 requirement {requirement} does not enforce a floor of {URLLIB3_FLOOR}")
    for probe in URLLIB3_FORBIDDEN_PROBES:
        if specifier.contains(probe, prereleases=True):
            failures.append(f"urllib3 requirement {requirement} permits vulnerable version {probe}")


def check_requires_python(metadata, failures):
    value = metadata.get("Requires-Python")
    if not value:
        failures.append("Requires-Python is missing")
        return
    specifier = SpecifierSet(value)
    for version in SUPPORTED_PYTHONS:
        if not specifier.contains(version):
            failures.append(f"Requires-Python {value} excludes supported Python {version}")
    for version in UNSUPPORTED_PYTHONS:
        if specifier.contains(version):
            failures.append(f"Requires-Python {value} admits unsupported Python {version}")


def check_release_tag(version, tag, failures):
    """Require tag == 'v' + version and a final, non-local release version."""
    if not tag.startswith("v"):
        failures.append(f"release tag {tag!r} must start with 'v'")
        return
    try:
        tag_version = Version(tag[1:])
    except InvalidVersion:
        failures.append(f"release tag {tag!r} is not a valid version")
        return
    if tag[1:] != str(version) or tag_version != version:
        failures.append(f"release tag {tag!r} does not match built version {version}")
    if version.is_devrelease or version.local is not None:
        failures.append(f"built version {version} is a development or local version and cannot be released")


def write_sums(paths, destination):
    lines = [f"{sha256_file(p)}  {p.name}" for p in sorted(paths, key=lambda p: p.name)]
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return lines


def check_sums(paths, sums_file, failures):
    """Require the SHA256SUMS file to list exactly the given artifacts with matching digests."""
    if not sums_file.is_file():
        failures.append(f"hash file {sums_file} is missing")
        return []
    expected = {}
    for number, line in enumerate(sums_file.read_text(encoding="utf-8").splitlines(), 1):
        match = SUMS_LINE.match(line)
        if not match:
            failures.append(f"malformed hash line {number} in {sums_file.name}")
            continue
        if match.group(2) in expected:
            failures.append(f"duplicate hash entry for {match.group(2)}")
        expected[match.group(2)] = match.group(1)
    actual = {p.name: sha256_file(p) for p in paths}
    if set(expected) != set(actual):
        failures.append(f"hash file lists {sorted(expected)} but artifacts are {sorted(actual)}")
    for name, digest in actual.items():
        if name in expected and expected[name] != digest:
            failures.append(f"sha256 mismatch for {name}")
    return [f"{actual[n]}  {n}" for n in sorted(actual)]


def verify(dist_dir, requirements_file, expected_tag=None, write_sums_to=None, check_sums_from=None):
    """Run all checks. Returns (summary dict, list of failure strings)."""
    failures = []
    summary = {"dist_dir": str(dist_dir)}
    wheel_path, sdist_path = find_artifacts(dist_dir, failures)
    if wheel_path is None:
        return summary, failures

    try:
        wheel_meta = read_wheel(wheel_path, failures)
        sdist_meta, sdist_requirements = read_sdist(sdist_path, failures)
    except (VerificationError, KeyError, zipfile.BadZipFile, tarfile.TarError, UnicodeDecodeError) as exc:
        failures.append(f"could not inspect artifacts: {exc}")
        return summary, failures

    for label, meta in (("wheel", wheel_meta), ("sdist", sdist_meta)):
        if canonicalize_name(meta.get("Name", "")) != PROJECT_NAME:
            failures.append(f"{label} metadata name {meta.get('Name')!r} is not {PROJECT_NAME}")
    try:
        version = Version(wheel_meta.get("Version", ""))
        if Version(sdist_meta.get("Version", "")) != version:
            failures.append(f"wheel version {version} differs from sdist version {sdist_meta.get('Version')}")
    except InvalidVersion as exc:
        failures.append(f"invalid version metadata: {exc}")
        return summary, failures
    summary["version"] = str(version)
    for label, path in (("wheel", wheel_path), ("sdist", sdist_path)):
        if f"-{version}" not in path.name:
            failures.append(f"{label} file name {path.name} does not carry version {version}")

    check_requires_python(wheel_meta, failures)
    if sdist_meta.get("Requires-Python") != wheel_meta.get("Requires-Python"):
        failures.append("sdist and wheel Requires-Python differ")

    try:
        declared = parse_requirement_lines(Path(requirements_file).read_text(encoding="utf-8"))
        shipped = parse_requirement_lines(sdist_requirements)
        wheel_requirements = runtime_requirements(wheel_meta)
    except (InvalidRequirement, VerificationError, OSError) as exc:
        failures.append(f"could not parse requirements: {exc}")
        return summary, failures
    if wheel_requirements != declared:
        failures.append(
            "wheel Requires-Dist differs from requirements.txt: "
            f"missing={sorted(declared - wheel_requirements)} extra={sorted(wheel_requirements - declared)}"
        )
    if shipped != declared:
        failures.append("sdist requirements.txt differs from the reviewed requirements.txt")
    check_urllib3_floor(wheel_requirements, failures)
    summary["requires_dist"] = sorted(wheel_requirements)
    summary["requires_python"] = wheel_meta.get("Requires-Python")

    if expected_tag is not None:
        check_release_tag(version, expected_tag, failures)
        summary["release_tag"] = expected_tag

    artifacts = [wheel_path, sdist_path]
    if write_sums_to is not None:
        if failures:
            failures.append("refusing to write hashes for artifacts that failed verification")
        else:
            summary["sha256"] = write_sums(artifacts, Path(write_sums_to))
    elif check_sums_from is not None:
        summary["sha256"] = check_sums(artifacts, Path(check_sums_from), failures)
    else:
        summary["sha256"] = [f"{sha256_file(p)}  {p.name}" for p in artifacts]
    return summary, failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dist_dir", type=Path)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--expected-tag", help="release tag to match; an empty value fails")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write-sums", type=Path)
    group.add_argument("--check-sums", type=Path)
    args = parser.parse_args(argv)

    if not args.dist_dir.is_dir():
        print(f"error: {args.dist_dir} is not a directory", file=sys.stderr)
        return 1
    summary, failures = verify(
        args.dist_dir,
        args.requirements,
        expected_tag=args.expected_tag,
        write_sums_to=args.write_sums,
        check_sums_from=args.check_sums,
    )
    summary["ok"] = not failures
    print(json.dumps(summary, indent=2, sort_keys=True))
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
