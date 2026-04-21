"""Tests for tessera.destructive_guard."""

from __future__ import annotations

from tessera.destructive_guard import (
    DestructiveCheckResult,
    Severity,
    check_destructive,
    check_tool_args,
)


class TestFilesystemDestruction:
    def test_rm_rf_root_blocks(self) -> None:
        r = check_destructive("rm -rf /")
        assert r.destructive
        assert r.should_block
        assert any(m.rule_id == "rm-rf-root" for m in r.matches)

    def test_rm_rf_home_blocks(self) -> None:
        r = check_destructive("rm -rf ~")
        assert r.destructive
        assert r.should_block

    def test_rm_rf_subdir_warns(self) -> None:
        r = check_destructive("rm -rf ./node_modules")
        assert r.destructive
        # subdirectory rm -rf is a WARN (still dangerous), not a BLOCK
        assert r.max_severity == Severity.WARN

    def test_rm_non_recursive_clean(self) -> None:
        r = check_destructive("rm file.txt")
        assert not r.destructive

    def test_shred_blocks(self) -> None:
        r = check_destructive("shred -uv important.txt")
        assert r.should_block

    def test_dd_to_disk_blocks(self) -> None:
        r = check_destructive("dd if=/dev/urandom of=/dev/sda bs=1M")
        assert r.should_block
        assert any(m.rule_id == "dd-of-device" for m in r.matches)

    def test_dd_to_file_clean(self) -> None:
        r = check_destructive("dd if=input.bin of=output.bin bs=1M")
        assert not r.destructive

    def test_mkfs_blocks(self) -> None:
        r = check_destructive("mkfs.ext4 /dev/sdb1")
        assert r.should_block


class TestGitDestruction:
    def test_force_push_main_blocks(self) -> None:
        r = check_destructive("git push --force origin main")
        assert r.should_block
        assert any("main" in m.matched_text.lower() for m in r.matches)

    def test_force_push_master_blocks(self) -> None:
        r = check_destructive("git push -f origin master")
        assert r.should_block

    def test_force_push_feature_warns(self) -> None:
        r = check_destructive("git push --force origin feature/new-thing")
        assert r.destructive
        assert not r.should_block  # WARN only

    def test_reset_hard_warns(self) -> None:
        r = check_destructive("git reset --hard HEAD~3")
        assert r.destructive
        assert r.max_severity == Severity.WARN

    def test_branch_force_delete_warns(self) -> None:
        r = check_destructive("git branch -D feature-branch")
        assert r.destructive
        assert r.max_severity == Severity.WARN

    def test_regular_push_clean(self) -> None:
        r = check_destructive("git push origin main")
        assert not r.destructive


class TestDatabaseDestruction:
    def test_drop_database_blocks(self) -> None:
        r = check_destructive("DROP DATABASE production;")
        assert r.should_block

    def test_drop_database_lowercase_blocks(self) -> None:
        r = check_destructive("drop database users_prod")
        assert r.should_block

    def test_drop_table_warns(self) -> None:
        r = check_destructive("DROP TABLE users;")
        assert r.destructive
        assert r.max_severity == Severity.WARN

    def test_truncate_warns(self) -> None:
        r = check_destructive("TRUNCATE TABLE logs;")
        assert r.destructive
        assert r.max_severity == Severity.WARN

    def test_delete_without_where_warns(self) -> None:
        r = check_destructive("DELETE FROM users;")
        assert r.destructive
        assert r.max_severity == Severity.WARN

    def test_delete_with_where_clean(self) -> None:
        r = check_destructive("DELETE FROM users WHERE id = 42;")
        assert not r.destructive

    def test_select_clean(self) -> None:
        r = check_destructive("SELECT * FROM users;")
        assert not r.destructive


class TestInfrastructure:
    def test_terraform_destroy_blocks(self) -> None:
        r = check_destructive("terraform destroy -auto-approve")
        assert r.should_block

    def test_kubectl_delete_all_blocks(self) -> None:
        r = check_destructive("kubectl delete all --all -n production")
        assert r.should_block

    def test_docker_prune_force_warns(self) -> None:
        r = check_destructive("docker system prune -af")
        assert r.destructive


class TestLockFiles:
    def test_delete_package_lock_warns(self) -> None:
        r = check_destructive("rm package-lock.json")
        assert r.destructive
        assert any(m.rule_id == "delete-lock-file" for m in r.matches)

    def test_delete_poetry_lock_warns(self) -> None:
        r = check_destructive("rm -f poetry.lock")
        assert r.destructive

    def test_delete_cargo_lock_warns(self) -> None:
        r = check_destructive("rm Cargo.lock && cargo build")
        assert r.destructive

    def test_delete_source_file_clean(self) -> None:
        r = check_destructive("rm tmp/output.txt")
        assert not r.destructive


class TestProcessManagement:
    def test_kill_9_init_blocks(self) -> None:
        r = check_destructive("kill -9 1")
        assert r.should_block

    def test_kill_regular_pid_clean(self) -> None:
        r = check_destructive("kill -9 12345")
        assert not r.destructive


class TestCheckToolArgs:
    def test_empty_args_clean(self) -> None:
        r = check_tool_args({})
        assert not r.destructive

    def test_none_args_clean(self) -> None:
        r = check_tool_args(None)  # type: ignore[arg-type]
        assert not r.destructive

    def test_command_arg_detected(self) -> None:
        r = check_tool_args({"command": "rm -rf /tmp/data"})
        assert r.destructive

    def test_sql_in_query_arg(self) -> None:
        r = check_tool_args({"query": "DROP DATABASE prod;"})
        assert r.should_block

    def test_non_string_args_ignored(self) -> None:
        r = check_tool_args({"count": 5, "flag": True})
        assert not r.destructive

    def test_multiple_args_concatenated(self) -> None:
        r = check_tool_args({
            "sql_before": "SELECT * FROM users;",
            "sql_after": "DROP TABLE users;",
        })
        assert r.destructive


class TestResultShape:
    def test_clean_result(self) -> None:
        r = check_destructive("ls -la")
        assert isinstance(r, DestructiveCheckResult)
        assert not r.destructive
        assert r.max_severity is None
        assert r.matches == ()

    def test_match_has_rule_id(self) -> None:
        r = check_destructive("rm -rf /etc")
        assert len(r.matches) >= 1
        assert all(m.rule_id for m in r.matches)

    def test_match_has_description(self) -> None:
        r = check_destructive("terraform destroy")
        assert r.matches[0].description
