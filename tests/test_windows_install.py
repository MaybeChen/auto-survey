from pathlib import Path


def test_windows_installer_forces_package_refresh_and_checks_cli_command():
    script = Path("deploy/windows/install.ps1").read_text(encoding="utf-8")
    assert "pip install --upgrade --force-reinstall ." in script
    assert '$CliHelp -notmatch "check-ai"' in script
