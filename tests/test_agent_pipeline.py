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


def transaction_packets(path: str, request_frame: int, stream: int):
    response_frame = request_frame + 1
    packets = packets_for(path)
    request = packets[0]["_source"]["layers"]
    response = packets[1]["_source"]["layers"]
    request["frame.number"] = str(request_frame)
    request["tcp.stream"] = str(stream)
    response["frame.number"] = str(response_frame)
    response["tcp.stream"] = str(stream)
    response["http.request_in"] = str(request_frame)
    return packets


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


def test_analysis_excludes_static_resources_before_persistence(tmp_path, monkeypatch):
    config = AppConfig(storage=StorageConfig(root=tmp_path / "data"))
    capture = tmp_path / "mixed.pcapng"
    capture.write_bytes(b"mixed-capture")
    observed = (
        transaction_packets("/users/1001", 1, 1)
        + transaction_packets("/favicon.ico", 3, 2)
        + transaction_packets("/assets/app.js", 5, 3)
    )
    monkeypatch.setattr(agent, "_runner", lambda _config: object())
    monkeypatch.setattr(
        agent,
        "probe_protocols",
        lambda _runner, _pcap: {
            "tcp": 6,
            "http": 6,
            "tls": 0,
            "http2": 0,
            "quic": 0,
        },
    )
    monkeypatch.setattr(agent, "extract_http1", lambda _runner, _pcap: observed)

    documents = agent.analyze_file(capture, config)
    assert [document["path"] for document in documents] == ["/users/{value}"]
    report = json.loads(
        (tmp_path / "data" / "output" / "reports" / "analysis-summary.json").read_text()
    )
    assert report["capturedTransactionCount"] == 3
    assert report["ignoredTransactionCount"] == 2
    assert report["transactionCount"] == 1
    redacted_files = list((tmp_path / "data" / "work" / "redacted").glob("*.json"))
    redacted = json.loads(redacted_files[0].read_text())
    assert [item["request"]["path"] for item in redacted] == ["/users/1001"]
