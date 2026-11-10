"""Tests for ci/release/verify_dist.py using synthetic wheel and sdist archives."""
import base64
import hashlib
import io
import tarfile
import zipfile

import pytest

import verify_dist

VERSION = "2.9.0"
REQUIREMENTS = "requests>=2.31.0,<3.0.0\nurllib3>=2.6.3,<3.0.0\n"


def metadata(version=VERSION, urllib3="urllib3<3.0.0,>=2.6.3", requires_python=">=3.10", name="gimme_aws_creds"):
    return (
        "Metadata-Version: 2.4\n"
        f"Name: {name}\n"
        f"Version: {version}\n"
        f"Requires-Python: {requires_python}\n"
        "Requires-Dist: requests<3.0.0,>=2.31.0\n"
        f"Requires-Dist: {urllib3}\n"
        "Provides-Extra: alicloud\n"
        'Requires-Dist: alibabacloud_sts20150401<2.0.0,>=1.2.0; extra == "alicloud"\n'
        "\nlong description\n"
    )


def record_hash(data):
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def make_wheel(directory, version=VERSION, meta=None, extra=None, notices=("LICENSE", "NOTICE"),
               tamper_record=False, tag="py3-none-any"):
    dist_info = f"gimme_aws_creds-{version}.dist-info"
    files = {
        "gimme_aws_creds/__init__.py": b"",
        f"gimme_aws_creds-{version}.data/scripts/gimme-aws-creds": b"#!python\n",
        f"{dist_info}/METADATA": (meta or metadata(version)).encode(),
        f"{dist_info}/WHEEL": f"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: {tag}\n".encode(),
    }
    for notice in notices:
        files[f"{dist_info}/licenses/{notice}"] = b"notice text\n"
    files.update(extra or {})
    record_lines = [f"{n},{record_hash(d)},{len(d)}" for n, d in files.items()]
    if tamper_record:
        record_lines[0] = f"gimme_aws_creds/__init__.py,{record_hash(b'other')},5"
    record_lines.append(f"{dist_info}/RECORD,,")
    files[f"{dist_info}/RECORD"] = ("\n".join(record_lines) + "\n").encode()
    path = directory / f"gimme_aws_creds-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as wheel:
        for name, data in files.items():
            wheel.writestr(name, data)
    return path


def make_sdist(directory, version=VERSION, meta=None, requirements=REQUIREMENTS, extra_members=None,
               omit=()):
    root = f"gimme_aws_creds-{version}"
    files = {
        "PKG-INFO": (meta or metadata(version)).encode(),
        "LICENSE": b"license\n",
        "NOTICE": b"notice\n",
        "requirements.txt": requirements.encode(),
        "setup.py": b"",
        "pyproject.toml": b"",
    }
    path = directory / f"{root}.tar.gz"
    with tarfile.open(path, "w:gz") as sdist:
        for name, data in files.items():
            if name in omit:
                continue
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            sdist.addfile(info, io.BytesIO(data))
        for info in extra_members or []:
            sdist.addfile(info, io.BytesIO(b"") if info.isfile() else None)
    return path


@pytest.fixture
def dist(tmp_path):
    directory = tmp_path / "dist"
    directory.mkdir()
    return directory


@pytest.fixture
def requirements_file(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text(REQUIREMENTS)
    return path


def run(dist, requirements_file, **kwargs):
    return verify_dist.verify(dist, requirements_file, **kwargs)


def test_valid_artifacts_pass_and_hashes_round_trip(dist, requirements_file):
    make_wheel(dist)
    make_sdist(dist)
    sums = dist / "SHA256SUMS"
    summary, failures = run(dist, requirements_file, expected_tag="v2.9.0", write_sums_to=sums)
    assert failures == []
    assert summary["version"] == "2.9.0"
    assert len(sums.read_text().splitlines()) == 2
    _, failures = run(dist, requirements_file, check_sums_from=sums)
    assert failures == []


def test_cli_exit_status(dist, requirements_file, capsys):
    make_wheel(dist)
    make_sdist(dist)
    assert verify_dist.main([str(dist), "--requirements", str(requirements_file)]) == 0
    assert verify_dist.main([str(dist), "--requirements", str(requirements_file), "--expected-tag", ""]) == 1
    assert "FAIL" in capsys.readouterr().err


def test_tampered_artifact_fails_hash_check(dist, requirements_file):
    wheel = make_wheel(dist)
    make_sdist(dist)
    sums = dist / "SHA256SUMS"
    _, failures = run(dist, requirements_file, write_sums_to=sums)
    assert failures == []
    wheel.write_bytes(wheel.read_bytes() + b"\0")
    _, failures = run(dist, requirements_file, check_sums_from=sums)
    assert any("sha256 mismatch" in f for f in failures)


def test_hash_file_must_list_exactly_the_artifacts(dist, requirements_file):
    make_wheel(dist)
    make_sdist(dist)
    sums = dist / "SHA256SUMS"
    run(dist, requirements_file, write_sums_to=sums)
    sums.write_text(sums.read_text() + "0" * 64 + "  extra.whl\n")
    _, failures = run(dist, requirements_file, check_sums_from=sums)
    assert any("hash file lists" in f for f in failures)


def test_refuses_to_hash_failing_artifacts(dist, requirements_file):
    make_wheel(dist, notices=("LICENSE",))
    make_sdist(dist)
    sums = dist / "SHA256SUMS"
    _, failures = run(dist, requirements_file, write_sums_to=sums)
    assert any("NOTICE" in f for f in failures)
    assert not sums.exists()


@pytest.mark.parametrize("constraint", [
    "urllib3<2.0.0,>=1.26.0",
    "urllib3<3.0.0,>=2.6.0",
    "urllib3<3",
    "urllib3>2.6.2",
    "urllib3>=2.6",
])
def test_vulnerable_urllib3_constraints_are_rejected(dist, tmp_path, constraint):
    requirements = tmp_path / "req.txt"
    requirements.write_text(f"requests>=2.31.0,<3.0.0\n{constraint}\n")
    make_wheel(dist, meta=metadata(urllib3=constraint))
    make_sdist(dist, requirements=requirements.read_text())
    _, failures = run(dist, requirements)
    assert any("urllib3" in f for f in failures), failures


@pytest.mark.parametrize("constraint", ["urllib3<3.0.0,>=2.6.3", "urllib3==2.8.0", "urllib3!=2.7.0,>=2.6.3"])
def test_patched_urllib3_constraints_are_accepted(constraint):
    failures = []
    verify_dist.check_urllib3_floor({f"{constraint}", "requests>=2"}, failures)
    assert failures == []


def test_conditional_or_missing_urllib3_is_rejected():
    failures = []
    verify_dist.check_urllib3_floor({'urllib3>=2.6.3; python_version < "3.12"'}, failures)
    assert any("conditional" in f for f in failures)
    failures = []
    verify_dist.check_urllib3_floor({"requests>=2"}, failures)
    assert any("exactly one" in f for f in failures)


def test_wheel_dependencies_must_match_requirements(dist, requirements_file):
    make_wheel(dist, meta=metadata().replace("Requires-Dist: requests<3.0.0,>=2.31.0\n", ""))
    make_sdist(dist)
    _, failures = run(dist, requirements_file)
    assert any("Requires-Dist differs" in f for f in failures)


def test_sdist_requirements_must_match_reviewed_file(dist, requirements_file):
    make_wheel(dist)
    make_sdist(dist, requirements=REQUIREMENTS + "evil>=1\n")
    _, failures = run(dist, requirements_file)
    assert any("sdist requirements.txt differs" in f for f in failures)


def test_requires_python_must_match_supported_range(dist, requirements_file):
    make_wheel(dist, meta=metadata(requires_python=">=3.9"))
    make_sdist(dist, meta=metadata(requires_python=">=3.9"))
    _, failures = run(dist, requirements_file)
    assert any("admits unsupported Python 3.9" in f for f in failures)


@pytest.mark.parametrize("tag,expected", [
    ("v2.9.0", None),
    ("2.9.0", "must start with 'v'"),
    ("v2.9.1", "does not match"),
    ("v2.9", "does not match"),
    ("", "must start with 'v'"),
])
def test_release_tag_must_match_version(dist, requirements_file, tag, expected):
    make_wheel(dist)
    make_sdist(dist)
    _, failures = run(dist, requirements_file, expected_tag=tag)
    if expected is None:
        assert failures == []
    else:
        assert any(expected in f for f in failures), failures


def test_dev_versions_cannot_be_released(dist, requirements_file):
    make_wheel(dist, version="2.9.0.dev1")
    make_sdist(dist, version="2.9.0.dev1")
    _, failures = run(dist, requirements_file, expected_tag="v2.9.0.dev1")
    assert any("development" in f for f in failures)


def test_wheel_and_sdist_versions_must_agree(dist, requirements_file):
    make_wheel(dist)
    make_sdist(dist, meta=metadata(version="2.9.1"))
    _, failures = run(dist, requirements_file)
    assert any("differs from sdist version" in f for f in failures)


def test_wheel_must_not_install_extra_top_level_packages(dist, requirements_file):
    make_wheel(dist, extra={"tests/__init__.py": b""})
    make_sdist(dist)
    _, failures = run(dist, requirements_file)
    assert any("unexpected top-level" in f for f in failures)


def test_wheel_record_mismatch_is_detected(dist, requirements_file):
    make_wheel(dist, tamper_record=True)
    make_sdist(dist)
    _, failures = run(dist, requirements_file)
    assert any("RECORD digest mismatch" in f for f in failures)


def test_wheel_must_be_pure_python(dist, requirements_file):
    make_wheel(dist, tag="cp313-cp313-linux_x86_64")
    make_sdist(dist)
    _, failures = run(dist, requirements_file)
    assert any("wheel tags" in f for f in failures)


def test_unsafe_sdist_members_are_rejected(dist, requirements_file):
    link = tarfile.TarInfo("gimme_aws_creds-2.9.0/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    traversal = tarfile.TarInfo("gimme_aws_creds-2.9.0/../escape")
    make_wheel(dist)
    make_sdist(dist, extra_members=[link, traversal])
    _, failures = run(dist, requirements_file)
    assert any("not a regular file" in f for f in failures)
    assert any("unsafe path" in f for f in failures)


def test_sdist_must_ship_notices(dist, requirements_file):
    make_wheel(dist)
    make_sdist(dist, omit=("NOTICE",))
    _, failures = run(dist, requirements_file)
    assert any("sdist is missing NOTICE" in f for f in failures)


def test_unexpected_files_in_dist_are_rejected(dist, requirements_file):
    make_wheel(dist)
    make_sdist(dist)
    (dist / "notes.txt").write_text("x")
    _, failures = run(dist, requirements_file)
    assert any("unexpected files" in f for f in failures)


def test_requires_exactly_one_wheel_and_sdist(dist, requirements_file):
    make_wheel(dist)
    _, failures = run(dist, requirements_file)
    assert any("exactly one wheel and one sdist" in f for f in failures)
