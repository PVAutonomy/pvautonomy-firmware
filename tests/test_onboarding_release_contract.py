"""Contract tests for the WP2-B Onboarding release publisher gate.

Covers:
1. The pinned release descriptor (exact keys/values, fail-closed mutations).
2. Descriptor/bundle alignment against a synthetic four-file bundle.
3. Static workflow contract of ``onboarding-release.yml`` (build-only PR
   path, dispatch-only publication, pinned actions, no secrets context,
   no mutation of historical releases or Pages).

These tests never contact GitHub or the network.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DESCRIPTOR_PATH = REPO_ROOT / "onboarding" / "releases" / "0.1.0.json"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "onboarding-release.yml"
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _load_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_onboarding_release_descriptor",
        SCRIPTS_DIR / "validate_onboarding_release_descriptor.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["validate_onboarding_release_descriptor"] = module
    spec.loader.exec_module(module)
    return module


validator = _load_validator()

CANONICAL = json.loads(DESCRIPTOR_PATH.read_text(encoding="utf-8"))
OTHER_VALID_SHA = "a" * 40


def _write_descriptor(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "descriptor.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _descriptor_errors(tmp_path: Path, mutate) -> list[str]:
    payload = json.loads(json.dumps(CANONICAL))
    mutate(payload)
    errors, _ = validator.validate_descriptor(_write_descriptor(tmp_path, payload))
    return errors


BINARY_PAYLOAD = b"\xe9wp2b-synthetic-onboarding\x00" * 32


def _make_bundle(tmp_path: Path, descriptor: dict | None = None) -> Path:
    descriptor = descriptor or CANONICAL
    bundle = tmp_path / "bundle"
    bundle.mkdir(exist_ok=True)
    sha = hashlib.sha256(BINARY_PAYLOAD).hexdigest()
    base_url = (
        "https://github.com/PVAutonomy/pvautonomy-firmware/releases/download/"
        + descriptor["release_tag"]
    )
    artifact_url = f"{base_url}/{descriptor['artifact_name']}"
    manifest_url = f"{base_url}/{descriptor['manifest_name']}"

    (bundle / descriptor["artifact_name"]).write_bytes(BINARY_PAYLOAD)
    (bundle / descriptor["checksum_name"]).write_text(
        f"{sha}  {descriptor['artifact_name']}\n", encoding="utf-8"
    )
    manifest = {
        "name": "PVAutonomy Edge101 Onboarding",
        "version": descriptor["version"],
        "manifest_version": 1,
        "home_assistant_domain": "esphome",
        "new_install_prompt_erase": False,
        "builds": [
            {
                "chipFamily": "ESP32",
                "parts": [{"path": artifact_url, "offset": 0}],
            }
        ],
    }
    metadata = {
        "artifact_class": descriptor["artifact_class"],
        "version": descriptor["version"],
        "project_version": descriptor["project_version"],
        "release_tag": descriptor["release_tag"],
        "artifact_name": descriptor["artifact_name"],
        "manifest_name": descriptor["manifest_name"],
        "source_repository": descriptor["source_repository"],
        "source_commit": descriptor["source_commit"],
        "esphome_version": descriptor["esphome_version"],
        "hardware_family": descriptor["hardware_family"],
        "board": descriptor["board"],
        "framework": descriptor["framework"],
        "sha256": sha,
        "size_bytes": len(BINARY_PAYLOAD),
        "manifest_version": 1,
        "immutable_artifact_url": artifact_url,
        "immutable_manifest_url": manifest_url,
    }
    (bundle / descriptor["manifest_name"]).write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    (bundle / descriptor["metadata_name"]).write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    return bundle


def _mutate_json(path: Path, mutate) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutate(payload)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Descriptor contract
# ---------------------------------------------------------------------------


class TestDescriptorContract:
    def test_canonical_descriptor_passes(self):
        errors, descriptor = validator.validate_descriptor(DESCRIPTOR_PATH)
        assert errors == []
        assert descriptor == CANONICAL

    def test_missing_field_fails(self, tmp_path):
        errors = _descriptor_errors(tmp_path, lambda d: d.pop("board"))
        assert any("missing required key 'board'" in e for e in errors)

    def test_extra_field_fails(self, tmp_path):
        errors = _descriptor_errors(
            tmp_path, lambda d: d.update(build_date="2026-07-22")
        )
        assert any("unexpected extra key 'build_date'" in e for e in errors)

    def test_wrong_source_repository_fails(self, tmp_path):
        errors = _descriptor_errors(
            tmp_path, lambda d: d.update(source_repository="gshubi/other")
        )
        assert any("source_repository" in e for e in errors)

    def test_wrong_but_valid_source_commit_fails(self, tmp_path):
        errors = _descriptor_errors(
            tmp_path, lambda d: d.update(source_commit=OTHER_VALID_SHA)
        )
        assert any("source_commit" in e for e in errors)

    @pytest.mark.parametrize(
        "bad_sha",
        ["HEAD", "main", CANONICAL["source_commit"].upper(), "abc123", ""],
    )
    def test_malformed_source_commit_fails(self, tmp_path, bad_sha):
        errors = _descriptor_errors(
            tmp_path, lambda d: d.update(source_commit=bad_sha)
        )
        assert any("source_commit" in e for e in errors)

    def test_wrong_esphome_version_fails(self, tmp_path):
        errors = _descriptor_errors(
            tmp_path, lambda d: d.update(esphome_version="2025.7.4")
        )
        assert any("esphome_version" in e for e in errors)

    def test_wrong_version_fails(self, tmp_path):
        errors = _descriptor_errors(tmp_path, lambda d: d.update(version="0.2.0"))
        assert errors

    def test_wrong_project_version_fails(self, tmp_path):
        errors = _descriptor_errors(
            tmp_path, lambda d: d.update(project_version="onboarding-9.9.9")
        )
        assert any("project_version" in e for e in errors)

    def test_wrong_release_tag_fails(self, tmp_path):
        errors = _descriptor_errors(
            tmp_path, lambda d: d.update(release_tag="vfactory")
        )
        assert any("release_tag" in e for e in errors)

    def test_production_ota_filename_fails(self, tmp_path):
        errors = _descriptor_errors(
            tmp_path, lambda d: d.update(artifact_name="firmware.ota.bin")
        )
        assert any("firmware.ota.bin" in e for e in errors)

    def test_secret_reference_fails(self, tmp_path):
        errors = _descriptor_errors(
            tmp_path, lambda d: d.update(source_yaml="esphome/secrets.yaml")
        )
        assert any("secrets.yaml" in e for e in errors)

    def test_duplicate_artifact_filename_fails(self, tmp_path):
        errors = _descriptor_errors(
            tmp_path,
            lambda d: d.update(checksum_name=d["artifact_name"]),
        )
        assert any("unique" in e or "checksum_name" in e for e in errors)


# ---------------------------------------------------------------------------
# 2. Bundle alignment
# ---------------------------------------------------------------------------


class TestBundleAlignment:
    def _errors(self, bundle: Path) -> list[str]:
        return validator.validate_bundle_alignment(CANONICAL, bundle)

    def test_valid_synthetic_bundle_passes(self, tmp_path):
        assert self._errors(_make_bundle(tmp_path)) == []

    def test_missing_bundle_file_fails(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        (bundle / CANONICAL["manifest_name"]).unlink()
        assert any("missing required file" in e for e in self._errors(bundle))

    def test_extra_bundle_file_fails(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        (bundle / "firmware.ota.bin").write_bytes(b"x")
        assert any("unexpected extra file" in e for e in self._errors(bundle))

    def test_zero_byte_binary_fails(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        (bundle / CANONICAL["artifact_name"]).write_bytes(b"")
        assert any("zero bytes" in e for e in self._errors(bundle))

    def test_checksum_mismatch_fails(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        (bundle / CANONICAL["artifact_name"]).write_bytes(b"tampered")
        assert any("checksum" in e for e in self._errors(bundle))

    def test_metadata_source_commit_mismatch_fails(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        _mutate_json(
            bundle / CANONICAL["metadata_name"],
            lambda m: m.update(source_commit=OTHER_VALID_SHA),
        )
        assert any("source_commit" in e for e in self._errors(bundle))

    def test_manifest_version_disagreement_fails(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        _mutate_json(
            bundle / CANONICAL["manifest_name"],
            lambda m: m.update(version="0.2.0"),
        )
        assert any("version disagrees" in e for e in self._errors(bundle))

    def test_metadata_size_disagreement_fails(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        _mutate_json(
            bundle / CANONICAL["metadata_name"],
            lambda m: m.update(size_bytes=m["size_bytes"] + 1),
        )
        assert any("size_bytes" in e for e in self._errors(bundle))

    def test_immutable_url_mismatch_fails(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        _mutate_json(
            bundle / CANONICAL["metadata_name"],
            lambda m: m.update(
                immutable_artifact_url="https://example.com/firmware.factory.bin"
            ),
        )
        assert any("immutable_artifact_url" in e for e in self._errors(bundle))

    def test_manifest_part_path_mismatch_fails(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        _mutate_json(
            bundle / CANONICAL["manifest_name"],
            lambda m: m["builds"][0]["parts"][0].update(
                path="https://example.com/edge101-onboarding-0.1.0.factory.bin"
            ),
        )
        assert any("immutable" in e for e in self._errors(bundle))

    def test_manifest_ota_key_fails(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        _mutate_json(
            bundle / CANONICAL["manifest_name"],
            lambda m: m["builds"][0].update(ota={"md5": "d41d8cd9"}),
        )
        assert any("forbidden Production-OTA" in e for e in self._errors(bundle))

    def test_nonzero_offset_fails(self, tmp_path):
        bundle = _make_bundle(tmp_path)
        _mutate_json(
            bundle / CANONICAL["manifest_name"],
            lambda m: m["builds"][0]["parts"][0].update(offset=4096),
        )
        assert any("offset" in e for e in self._errors(bundle))


# ---------------------------------------------------------------------------
# 3. Workflow static contract (R2 trust boundary: validation-only PR path,
#    promote-only manual publication of an already staged draft)
# ---------------------------------------------------------------------------

RAW_WORKFLOW = WORKFLOW_PATH.read_text(encoding="utf-8")
WORKFLOW = yaml.safe_load(RAW_WORKFLOW)
# PyYAML parses the bare `on:` key as boolean True.
TRIGGERS = WORKFLOW.get("on") or WORKFLOW.get(True)
JOBS = WORKFLOW["jobs"]
VALIDATE_JOB = JOBS["validate-contract"]
PUBLISH_JOB = JOBS["publish"]

WP2B_FILES = [
    "README.md",
    "onboarding/releases/0.1.0.json",
    "scripts/validate_onboarding_release_descriptor.py",
    "tests/test_onboarding_release_contract.py",
    ".github/workflows/onboarding-release.yml",
]

PINNED_SOURCE_COMMIT = "bc761fc58fca1982df360c9df2dbf90a950e3e5a"


class TestWorkflowStaticContract:
    # --- triggers -----------------------------------------------------------

    def test_only_pull_request_and_dispatch_triggers(self):
        assert sorted(TRIGGERS.keys()) == ["pull_request", "workflow_dispatch"]

    def test_no_forbidden_triggers(self):
        for forbidden in (
            "push",
            "schedule",
            "release",
            "repository_dispatch",
            "pull_request_target",
        ):
            assert forbidden not in TRIGGERS
        assert "pull_request_target" not in RAW_WORKFLOW

    def test_pull_request_paths_are_the_wp2b_files(self):
        assert sorted(TRIGGERS["pull_request"]["paths"]) == sorted(WP2B_FILES)

    def test_dispatch_requires_confirmation_input(self):
        inputs = TRIGGERS["workflow_dispatch"]["inputs"]
        assert list(inputs.keys()) == ["confirm_release"]
        assert inputs["confirm_release"]["required"] is True
        assert inputs["confirm_release"]["type"] == "string"

    def test_exact_typed_confirmation_is_required(self):
        assert WORKFLOW["env"]["REQUIRED_CONFIRMATION"] == "PUBLISH onboarding-v0.1.0"
        # Both jobs compare against the required confirmation fail-closed.
        assert RAW_WORKFLOW.count('"${CONFIRM}" != "${REQUIRED_CONFIRMATION}"') >= 2

    # --- permission split ---------------------------------------------------

    def test_global_permissions_read_only(self):
        assert WORKFLOW["permissions"] == {"contents": "read"}

    def test_validate_job_has_no_write_permissions(self):
        assert "permissions" not in VALIDATE_JOB

    def test_publish_job_write_scope_and_dispatch_only(self):
        assert PUBLISH_JOB["permissions"] == {"contents": "write"}
        assert PUBLISH_JOB["if"] == "github.event_name == 'workflow_dispatch'"
        assert PUBLISH_JOB["needs"] == "validate-contract"

    def test_write_permission_confined_to_publish_job(self):
        for name, job in JOBS.items():
            if name == "publish":
                continue
            assert "permissions" not in job or "write" not in str(job["permissions"])
        assert "publish is only reachable via workflow_dispatch" in RAW_WORKFLOW

    def test_publication_requires_main_ref(self):
        assert 'refs/heads/main' in RAW_WORKFLOW
        assert "publication is only authorized from refs/heads/main" in RAW_WORKFLOW

    # --- trust boundary: no private source access ---------------------------

    def test_no_private_source_checkout(self):
        # The public publisher never checks out or references the private
        # canonical source repository.
        assert "pvautonomy-config" not in RAW_WORKFLOW
        assert "repository: PVAutonomy" not in RAW_WORKFLOW

    def test_no_secrets_context_or_custom_token(self):
        assert "secrets." not in RAW_WORKFLOW
        assert "${{ github.token }}" in RAW_WORKFLOW
        # \bPAT\b avoids matching the legitimate HTTP PATCH verb.
        assert re.search(r"\bPAT\b", RAW_WORKFLOW) is None
        for needle in ("token_input", "private_key", "app_id"):
            assert needle not in RAW_WORKFLOW

    def test_pr_path_is_validation_only(self):
        lowered = RAW_WORKFLOW.lower()
        assert "esphome" not in lowered
        assert "compile" not in lowered
        assert "build_release_bundle" not in RAW_WORKFLOW
        assert "validate_release_bundle" not in RAW_WORKFLOW
        assert "upload-artifact" not in RAW_WORKFLOW
        assert "download-artifact" not in RAW_WORKFLOW
        assert "retention-days" not in RAW_WORKFLOW

    def test_validation_job_name_is_honest(self):
        assert VALIDATE_JOB["name"] == "Validate Onboarding publisher contract"
        assert "Build + validate" not in RAW_WORKFLOW

    # --- staged-draft preconditions -----------------------------------------

    def test_publisher_requires_existing_staged_draft(self):
        assert "Require exactly one staged draft" in RAW_WORKFLOW
        assert "must stage exactly one draft first" in RAW_WORKFLOW
        assert "target_commitish" in RAW_WORKFLOW
        assert "bound to the verified publisher commit" in RAW_WORKFLOW

    def test_refusal_of_existing_tag_or_published_release(self):
        assert 'git ls-remote --exit-code origin "refs/tags/${RELEASE_TAG}"' in RAW_WORKFLOW
        assert "already exists" in RAW_WORKFLOW
        assert '.draft == false)] | length' in RAW_WORKFLOW

    # --- mutation surface ---------------------------------------------------

    def test_workflow_cannot_create_draft_or_release(self):
        assert "gh release create" not in RAW_WORKFLOW
        assert "-X POST" not in RAW_WORKFLOW

    def test_workflow_cannot_upload_or_replace_assets(self):
        assert "gh release upload" not in RAW_WORKFLOW
        assert "uploads.github.com" not in RAW_WORKFLOW

    def test_no_release_or_tag_deletion(self):
        assert "gh release delete" not in RAW_WORKFLOW
        assert "-X DELETE" not in RAW_WORKFLOW
        assert "Nothing was deleted" in RAW_WORKFLOW

    def test_exactly_one_release_mutating_patch(self):
        assert RAW_WORKFLOW.count("-X PATCH") == 1
        patch_index = RAW_WORKFLOW.index("-X PATCH")
        promote_index = RAW_WORKFLOW.index("Promote the verified draft")
        assert promote_index < patch_index

    def test_promotion_patch_flags(self):
        assert "-F draft=false" in RAW_WORKFLOW
        assert "-F prerelease=false" in RAW_WORKFLOW
        assert "make_latest=false" in RAW_WORKFLOW

    # --- ordering ------------------------------------------------------------

    def test_download_and_validation_precede_promotion(self):
        promote = RAW_WORKFLOW.index("Promote the verified draft")
        assert RAW_WORKFLOW.index("Download the four staged draft assets") < promote
        assert RAW_WORKFLOW.index("Validate downloaded candidate against the descriptor") < promote
        assert RAW_WORKFLOW.index("Verify draft asset sizes and digests") < promote

    def test_latest_identity_captured_before_promotion(self):
        capture = RAW_WORKFLOW.index("Capture pre-publication latest release identity")
        promote = RAW_WORKFLOW.index("Promote the verified draft")
        assert capture < promote
        assert "PRE_LATEST_ID" in RAW_WORKFLOW
        assert "PRE_LATEST_TAG" in RAW_WORKFLOW

    def test_post_publication_verification_after_promotion(self):
        promote = RAW_WORKFLOW.index("Promote the verified draft")
        verify = RAW_WORKFLOW.index("Verify published release state")
        assert promote < verify

    def test_post_publication_verification_checks(self):
        for required in (
            "still a draft",
            "prerelease",
            "published_at",
            'git/ref/tags/${RELEASE_TAG}',
            "published size",
            "sha256:",
            "latest release changed",
        ):
            assert required in RAW_WORKFLOW, f"missing verification check: {required}"
        assert WORKFLOW["env"]["RELEASE_TITLE"] == "PVAutonomy Edge101 Onboarding Image 0.1.0"
        # Tag must resolve to the verified publisher commit.
        assert 'commit:{github_sha}' in RAW_WORKFLOW

    def test_incident_message_on_verification_failure(self):
        assert "Planner-led incident review required" in RAW_WORKFLOW

    # --- hygiene -------------------------------------------------------------

    def test_all_actions_pinned_by_sha(self):
        uses = re.findall(r"uses:\s*(\S+)", RAW_WORKFLOW)
        assert uses, "workflow must use pinned actions"
        for entry in uses:
            assert re.search(r"@[0-9a-f]{40}$", entry), f"unpinned action: {entry}"
            assert entry.startswith("actions/"), f"non-official action: {entry}"

    def test_historical_releases_and_pages_never_addressed(self):
        for legacy in ("vfactory", "v1.0.3", "v1.0.4", "gh-pages"):
            assert legacy not in RAW_WORKFLOW

    def test_concurrency_is_fixed_and_never_cancels(self):
        concurrency = WORKFLOW["concurrency"]
        assert concurrency["group"] == "onboarding-release-0.1.0"
        assert concurrency["cancel-in-progress"] is False

    # --- source pin lives in the descriptor contract -------------------------

    def test_source_commit_pinned_by_descriptor_contract(self):
        assert CANONICAL["source_commit"] == PINNED_SOURCE_COMMIT
        assert (
            validator.EXPECTED_DESCRIPTOR["source_commit"] == PINNED_SOURCE_COMMIT
        )
