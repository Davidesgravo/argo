from argo.jsonl import append_jsonl, read_jsonl, read_models, write_jsonl
from argo.schema import Hit


def test_append_then_read(tmp_path):
    p = tmp_path / "sub" / "x.jsonl"
    append_jsonl(p, {"a": 1})
    append_jsonl(p, {"a": 2})
    assert read_jsonl(p) == [{"a": 1}, {"a": 2}]


def test_read_missing_file_is_empty(tmp_path):
    assert read_jsonl(tmp_path / "none.jsonl") == []


def test_write_replaces_and_read_models(tmp_path):
    p = tmp_path / "h.jsonl"
    write_jsonl(p, [{"category": "exec", "path": "a.js", "line": 1, "snippet": "eval("}])
    write_jsonl(p, [{"category": "network", "path": "b.js", "line": 2, "snippet": "fetch("}])
    hits = read_models(p, Hit)
    assert [h.category for h in hits] == ["network"]
