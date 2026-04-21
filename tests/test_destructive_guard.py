"""Tests for tessera.destructive_guard."""

from __future__ import annotations

import re

import pytest

from tessera.destructive_guard import (
    DestructiveGuard,
    DestructivePattern,
    GuardMatch,
    GuardResult,
)


@pytest.fixture
def guard() -> DestructiveGuard:
    return DestructiveGuard()


class TestFilesystem:
    @pytest.mark.parametrize("command", [
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "rm -rf ~/*",
        "rm -rf $HOME",
        "rm -rf $HOME/*",
        "rm -Rf /",
        "rm -fr /",
    ])
    def test_rm_rf_root_blocked(self, guard: DestructiveGuard, command: str) -> None:
        r = guard.check("bash.run", {"command": command})
        assert not r.allowed
        assert r.matches[0].category == "filesystem"
        assert r.matches[0].pattern_id in ("fs.rm_rf_root", "fs.no_preserve_root")

    def test_rm_rf_specific_path_allowed(self, guard: DestructiveGuard) -> None:
        """rm -rf of a specific workspace directory is legitimate."""
        r = guard.check("bash.run", {"command": "rm -rf /tmp/my-workspace/build"})
        assert r.allowed

    def test_rm_rf_node_modules_allowed(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "rm -rf node_modules"})
        assert r.allowed

    def test_no_preserve_root_always_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "rm --no-preserve-root -rf /var"})
        assert not r.allowed

    def test_dd_to_disk_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "dd if=/dev/urandom of=/dev/sda bs=1M"})
        assert not r.allowed
        assert r.matches[0].pattern_id == "fs.dd_to_disk"

    def test_dd_to_file_allowed(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "dd if=input.bin of=output.bin"})
        assert r.allowed

    def test_mkfs_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "mkfs.ext4 /dev/sdb1"})
        assert not r.allowed

    def test_find_delete_at_root_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "find / -name '*.log' -delete"})
        assert not r.allowed

    def test_find_delete_in_workspace_allowed(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "find ./build -name '*.tmp' -delete"})
        assert r.allowed

    def test_chmod_777_root_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "chmod -R 777 /"})
        assert not r.allowed


class TestHost:
    def test_forkbomb_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": ":(){ :|:& };:"})
        assert not r.allowed
        assert r.matches[0].pattern_id == "host.forkbomb"

    def test_shutdown_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "shutdown -h now"})
        assert not r.allowed

    def test_poweroff_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "poweroff"})
        assert not r.allowed


class TestSQL:
    @pytest.mark.parametrize("sql", [
        "DROP TABLE users;",
        "drop database production",
        "DROP SCHEMA public CASCADE",
        "TRUNCATE TABLE events",
        "TRUNCATE events",
        "DELETE FROM accounts;",
        "DELETE FROM accounts WHERE 1=1",
        "DELETE FROM accounts WHERE true",
        "UPDATE users SET active=0;",
    ])
    def test_destructive_sql_blocked(self, guard: DestructiveGuard, sql: str) -> None:
        r = guard.check("db.query.write", {"sql": sql})
        assert not r.allowed
        assert r.matches[0].category == "sql"

    def test_scoped_delete_allowed(self, guard: DestructiveGuard) -> None:
        r = guard.check("db.query.write", {"sql": "DELETE FROM accounts WHERE id = 42"})
        assert r.allowed

    def test_scoped_update_allowed(self, guard: DestructiveGuard) -> None:
        r = guard.check("db.query.write", {"sql": "UPDATE users SET active = 0 WHERE id = 42"})
        assert r.allowed

    def test_select_allowed(self, guard: DestructiveGuard) -> None:
        r = guard.check("db.query.read", {"sql": "SELECT * FROM accounts"})
        assert r.allowed


class TestGit:
    def test_force_push_to_main_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "git push --force origin main"})
        assert not r.allowed
        assert r.matches[0].pattern_id == "git.push_force_protected"

    def test_force_push_to_master_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "git push -f origin master"})
        assert not r.allowed

    def test_force_push_to_feature_allowed(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "git push --force origin feature/x"})
        assert r.allowed

    def test_force_with_lease_allowed(self, guard: DestructiveGuard) -> None:
        """--force-with-lease is the safer variant; not blocked here.
        (An intent scanner can still flag it if desired.)"""
        r = guard.check("bash.run", {"command": "git push --force-with-lease origin feature/x"})
        assert r.allowed

    def test_normal_push_allowed(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "git push origin main"})
        assert r.allowed

    def test_clean_fdx_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "git clean -fdx"})
        assert not r.allowed

    def test_reset_hard_to_remote_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "git reset --hard origin/main"})
        assert not r.allowed


class TestInfrastructure:
    def test_terraform_destroy_auto_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {
            "command": "terraform destroy -auto-approve -var-file=prod.tfvars",
        })
        assert not r.allowed
        assert r.matches[0].pattern_id == "iac.terraform_destroy_auto"

    def test_terraform_destroy_interactive_allowed(self, guard: DestructiveGuard) -> None:
        # Without -auto-approve, destroy requires human confirmation
        r = guard.check("bash.run", {"command": "terraform destroy"})
        assert r.allowed

    def test_k8s_delete_all_force_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {
            "command": "kubectl delete pods --all --force --grace-period=0 -n prod",
        })
        assert not r.allowed

    def test_aws_s3_rb_force_blocks(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "aws s3 rb s3://my-bucket --force"})
        assert not r.allowed


class TestArgFlattening:
    def test_nested_arg_path(self, guard: DestructiveGuard) -> None:
        r = guard.check("http.post", {
            "headers": {"x-run": "sudo rm -rf /"},
            "body": "{}",
        })
        assert not r.allowed
        assert r.matches[0].arg_path == "headers.x-run"

    def test_list_arg_path(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {
            "args": ["echo", "rm -rf /"],
        })
        assert not r.allowed
        assert "args[1]" in r.matches[0].arg_path

    def test_string_arg_path(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", "rm -rf /")
        assert not r.allowed
        assert r.matches[0].arg_path == "$"

    def test_none_args_allowed(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", None)
        assert r.allowed


class TestCustomPatterns:
    def test_extra_pattern(self) -> None:
        extra = DestructivePattern(
            id="custom.disable_audit",
            description="disable audit logging",
            regex=re.compile(r"(?i)\bAUDIT\s+OFF\b"),
            category="custom",
        )
        g = DestructiveGuard(extra=[extra])
        r = g.check("db.query.write", {"sql": "SET AUDIT OFF"})
        assert not r.allowed
        assert r.matches[0].pattern_id == "custom.disable_audit"

    def test_scoped_pattern_only_applies_to_tool(self) -> None:
        scoped = DestructivePattern(
            id="custom.db_only",
            description="something only bad in db",
            regex=re.compile(r"dangerous"),
            category="custom",
            applies_to_tools=("db.query.write",),
        )
        g = DestructiveGuard(extra=[scoped])
        # Matches in db tool
        assert not g.check("db.query.write", {"sql": "dangerous"}).allowed
        # Does not match in shell tool
        assert g.check("bash.run", {"command": "dangerous"}).allowed

    def test_replace_default_patterns(self) -> None:
        g = DestructiveGuard(patterns=[], include_defaults=False)
        r = g.check("bash.run", {"command": "rm -rf /"})
        assert r.allowed  # no patterns configured


class TestGuardResult:
    def test_primary_reason_on_allow(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "ls -la"})
        assert r.allowed
        assert r.primary_reason == ""

    def test_primary_reason_on_deny(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "rm -rf /"})
        assert not r.allowed
        assert "rm_rf_root" in r.primary_reason
        assert "rm -rf on root or home" in r.primary_reason

    def test_match_preserves_matched_text(self, guard: DestructiveGuard) -> None:
        r = guard.check("bash.run", {"command": "rm -rf / && echo hi"})
        assert not r.allowed
        assert "rm" in r.matches[0].matched_text
