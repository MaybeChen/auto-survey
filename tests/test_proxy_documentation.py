from pathlib import Path


def test_windows_proxy_documentation_covers_wininet_mapping_and_407():
    readme = Path("README.md").read_text(encoding="utf-8")
    assert 'AI_HTTPS_PROXY = "http://proxyau.huawei.com:8080"' in readme
    assert '-ProxyUseDefaultCredentials' in readme
    assert 'HTTP 407' in readme
    assert 'proxy_url_env: "AI_HTTPS_PROXY"' in readme
