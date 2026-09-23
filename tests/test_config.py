"""Configuration: .env loading, placeholder detection and live settings."""

import os

import pytest

from webhooks import config

# Assembled at runtime so nothing on disk looks like a credential.
DEMO_SECRET = "demo" + "-" + "secret" + "-" + "123"


# --- .env parsing -----------------------------------------------------------
def test_parse_env_file_handles_common_syntax():
    text = "\n".join(
        [
            "# a comment",
            "",
            "PLAIN=value",
            "export EXPORTED=yes",
            "SPACED = padded value  ",
            "INLINE=abc # trailing comment",
            "HASH_IN_VALUE=abc#def",
            "SINGLE='single # not a comment'",
            'DOUBLE="line1\\nline2 \\"quoted\\""',
            "EMPTY=",
            "not a valid line",
        ]
    )
    values = config.parse_env_file(text)
    assert values["PLAIN"] == "value"
    assert values["EXPORTED"] == "yes"
    assert values["SPACED"] == "padded value"
    assert values["INLINE"] == "abc"
    assert values["HASH_IN_VALUE"] == "abc#def"
    assert values["SINGLE"] == "single # not a comment"
    assert values["DOUBLE"] == 'line1\nline2 "quoted"'
    assert values["EMPTY"] == ""
    assert "not a valid line" not in values


def test_load_env_file_reads_dotenv_from_cwd(tmp_path):
    (tmp_path / ".env").write_text(f"GITHUB_WEBHOOK_SECRET={DEMO_SECRET}\n", encoding="utf-8")
    applied = config.load_env_file()
    assert applied == {"GITHUB_WEBHOOK_SECRET": DEMO_SECRET}
    assert config.get_secret("github") == DEMO_SECRET


def test_real_environment_wins_over_env_file(tmp_path):
    (tmp_path / ".env").write_text(
        f"GITHUB_WEBHOOK_SECRET=from-file-{DEMO_SECRET}\nWEBHOOK_PORT=9100\n", encoding="utf-8"
    )
    os.environ["GITHUB_WEBHOOK_SECRET"] = f"from-shell-{DEMO_SECRET}"
    config.load_env_file()
    assert config.get_secret("github") == f"from-shell-{DEMO_SECRET}"
    assert config.DEFAULT_PORT == 9100  # unset in the shell, so the file applies


def test_override_flag_lets_file_win(tmp_path):
    env_file = tmp_path / "custom.env"
    env_file.write_text("WEBHOOK_DB=from-file.db\n", encoding="utf-8")
    os.environ["WEBHOOK_DB"] = "from-shell.db"
    config.load_env_file(env_file, override=True)
    assert config.DEFAULT_DB == "from-file.db"


def test_missing_implicit_env_file_is_fine_but_explicit_one_is_an_error(tmp_path):
    assert config.load_env_file() == {}
    with pytest.raises(FileNotFoundError):
        config.load_env_file(tmp_path / "nope.env")


def test_env_file_with_bom_is_parsed(tmp_path):
    (tmp_path / ".env").write_bytes(b"\xef\xbb\xbfWEBHOOK_HOST=0.0.0.0\n")  # UTF-8 BOM (Notepad)
    config.load_env_file()
    assert config.DEFAULT_HOST == "0.0.0.0"


# --- live settings ----------------------------------------------------------
def test_settings_are_read_live_with_defaults():
    assert config.DEFAULT_DB == "webhooks.db"
    assert config.DEFAULT_PORT == 8000
    assert config.DEFAULT_TOLERANCE == 300
    os.environ["WEBHOOK_TIMESTAMP_TOLERANCE"] = "42"
    assert config.DEFAULT_TOLERANCE == 42


def test_invalid_numeric_setting_names_the_variable():
    os.environ["WEBHOOK_PORT"] = "eighty"
    with pytest.raises(ValueError, match="WEBHOOK_PORT"):
        config.DEFAULT_PORT


def test_unknown_attribute_still_raises():
    with pytest.raises(AttributeError):
        config.NOT_A_SETTING


# --- secrets and placeholders ----------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [
        ("whsec_XXXXXXXXXXXXXXXXXXXXXXXXXXXX", True),
        ("use-a-long-random-string-here", True),
        ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", True),
        ("  ", True),
        (None, True),
        ("CHANGEME", True),
        (DEMO_SECRET, False),
    ],
)
def test_is_placeholder(value, expected):
    assert config.is_placeholder(value) is expected


def test_secret_status_distinguishes_unset_placeholder_and_set():
    assert config.secret_status("stripe").state == "unset"
    os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    status = config.secret_status("stripe")
    assert status.state == "placeholder"
    assert status.usable
    assert "placeholder" in status.describe()
    assert "XXXX" not in repr(status)  # the value never leaks through repr
    os.environ["STRIPE_WEBHOOK_SECRET"] = DEMO_SECRET
    assert config.secret_status("stripe").state == "set"
    assert config.secret_status("nope").state == "unknown-provider"
    assert not config.secret_status("nope").usable


def test_get_secret_placeholder_needs_opt_in():
    os.environ["GITHUB_WEBHOOK_SECRET"] = "use-a-long-random-string-here"
    assert config.get_secret("github") is None
    assert config.get_secret("github", allow_placeholder=True) == "use-a-long-random-string-here"
    assert config.all_secrets()["github"] is None
    assert config.all_secrets(allow_placeholder=True)["github"] == "use-a-long-random-string-here"


def test_describe_messages_name_the_variable():
    assert config.secret_status("slack").describe() == "SLACK_SIGNING_SECRET is not set"
    os.environ["SLACK_SIGNING_SECRET"] = DEMO_SECRET
    assert config.secret_status("slack").describe() == "SLACK_SIGNING_SECRET is set"
