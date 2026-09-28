import json
from pathlib import Path

from src import agent
from src.config import AppConfig, StorageConfig


def packet(**fields):
    return {"_source": {"layers": fields}}


def packets_for(path: str):
    return [
        packet(
            **{
                "frame.number": "1",
                "tcp.stream": "1",
                "http.request.method": "GET",
                "http.host": "api.test",
                "http.request.uri": path,
            }
        ),
        packet(
            **{
                "frame.number": "2",
                "tcp.stream": "1",
                "http.response.code": "200",
                "http.request_in": "1",
                "http.content_type": "application/json",
                "http.file_data": "7b226f6b223a747275657d",
            }
        ),
    ]


def test_analysis_persists_and_rebuilds_cross_capture_endpoints(tmp_path, monkeypatch):
    config = AppConfig(storage=StorageConfig(root=tmp_path / "data"))
    first = tmp_path / "first.pcapng"
    second = tmp_path / "second.pcapng"
    first.write_bytes(b"capture-one")
    second.write_bytes(b"capture-two")
    monkeypatch.setattr(agent, "_runner", lambda _config: object())
    monkeypatch.setattr(
        agent,
        "probe_protocols",
        lambda _runner, _pcap: {"tcp": 2, "http": 2, "tls": 0, "http2": 0, "quic": 0},
    )
    monkeypatch.setattr(
        agent,
        "extract_http1",
        lambda _runner, pcap: packets_for(
            "/users/1001" if pcap.name == "first.pcapng" else "/users/1002"
        ),
    )

    agent.analyze_file(first, config)
    stale = tmp_path / "data" / "output" / "interfaces" / "stale.json"
    stale.write_text("{}")
    documents = agent.analyze_file(second, config)
    assert not stale.exists()
    assert len(documents) == 1
    assert documents[0]["path"] == "/users/{value}"
    assert documents[0]["statistics"]["sampleCount"] == 2
    assert documents[0]["evidence"]["observedPaths"] == [
        "/users/1001",
        "/users/1002",
    ]
    catalog = json.loads(
        (tmp_path / "data" / "output" / "api-catalog.json").read_text()
    )
    assert catalog["endpointCount"] == 1
    assert catalog["endpoints"][0]["sampleCount"] == 2
    assert agent.analyze_file(second, config) == []
