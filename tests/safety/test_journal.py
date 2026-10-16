import json
from datetime import datetime, timedelta

from app_triage.safety.journal import FixSession, Journal, JournalEntry


def make_entry(index=0, status="applied", **kw):
    return JournalEntry(
        index=index,
        kind=kw.get("kind", "disable_autorun"),
        target=kw.get("target", r"HKCU\Software\Run\Foo"),
        params=kw.get("params", {"value": "x"}),
        status=status,
        backup=kw.get("backup", {"reg": "foo.reg"}),
        message=kw.get("message", "中文消息"),
    )


def fixed_clock(*times):
    it = iter(times)
    last = [None]

    def now():
        try:
            last[0] = next(it)
        except StopIteration:
            pass
        return last[0]

    return now


T0 = datetime(2026, 10, 16, 9, 30, 5)


def test_journal_persists_and_reloads(tmp_path):
    journal = Journal(tmp_path / "sessions", now=lambda: T0)
    session = journal.begin("清理 WPS 残留")
    assert session.id == "20261016-093005"
    assert session.dir == tmp_path / "sessions" / session.id
    assert session.created == T0.isoformat(timespec="seconds")

    session.record(make_entry(0))
    session.record(make_entry(1, status="failed", message="拒绝访问"))
    updated = make_entry(0, status="undone")
    session.update(updated)
    assert [e.status for e in session.entries] == ["undone", "failed"]

    raw = json.loads((session.dir / "journal.json").read_text(encoding="utf-8"))
    assert set(raw) == {"id", "created", "label", "entries"}
    assert "清理 WPS 残留" in (session.dir / "journal.json").read_text(encoding="utf-8")

    loaded = Journal(tmp_path / "sessions").load(session.id)
    assert loaded.id == session.id
    assert loaded.label == "清理 WPS 残留"
    assert loaded.created == session.created
    assert loaded.entries == session.entries
    assert loaded.entries[1].message == "拒绝访问"
    # no temp files left behind
    assert [p.name for p in session.dir.iterdir()] == ["journal.json"]


def test_update_unknown_index_raises(tmp_path):
    session = Journal(tmp_path, now=lambda: T0).begin("x")
    session.record(make_entry(0))
    try:
        session.update(make_entry(5))
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError")


def test_backup_and_quarantine_dirs_created_on_demand(tmp_path):
    session = Journal(tmp_path, now=lambda: T0).begin("x")
    assert not (session.dir / "backup").exists()
    p = session.backup_path("foo.reg")
    assert p == session.dir / "backup" / "foo.reg"
    assert p.parent.is_dir()
    q = session.quarantine_dir()
    assert q == session.dir / "quarantine"
    assert q.is_dir()


def test_session_id_collision_suffix(tmp_path):
    journal = Journal(tmp_path, now=lambda: T0)
    ids = [journal.begin("a").id for _ in range(3)]
    assert ids == ["20261016-093005", "20261016-093005-2", "20261016-093005-3"]


def test_sessions_newest_first(tmp_path):
    clock = fixed_clock(
        T0, T0 + timedelta(minutes=5), T0 - timedelta(days=1), T0 + timedelta(minutes=5)
    )
    journal = Journal(tmp_path, now=clock)
    a = journal.begin("a")
    b = journal.begin("b")
    c = journal.begin("c")
    d = journal.begin("d")  # same second as b -> suffix, sorts after b
    assert d.id == b.id + "-2"
    assert [s.label for s in journal.sessions()] == ["d", "b", "a", "c"]
    assert c.id < a.id


def test_sessions_ignores_stray_entries(tmp_path):
    journal = Journal(tmp_path, now=lambda: T0)
    journal.begin("real")
    (tmp_path / "stray.txt").write_text("x")
    (tmp_path / "emptydir").mkdir()
    assert [s.label for s in journal.sessions()] == ["real"]
    assert Journal(tmp_path / "missing").sessions() == []


def test_corrupt_journal_loads_empty(tmp_path):
    journal = Journal(tmp_path, now=lambda: T0)
    session = journal.begin("good")
    (session.dir / "journal.json").write_text("{not json", encoding="utf-8")
    loaded = journal.load(session.id)
    assert loaded.entries == []
    assert loaded.label == "（日志损坏）"
    assert loaded.id == session.id
    assert [s.id for s in journal.sessions()] == [session.id]

    # structurally wrong content is corrupt too
    (session.dir / "journal.json").write_text(
        json.dumps({"id": session.id, "created": "x", "label": "y", "entries": [{"index": 1}]}),
        encoding="utf-8",
    )
    assert journal.load(session.id).label == "（日志损坏）"
    (session.dir / "journal.json").write_text("[]", encoding="utf-8")
    assert journal.load(session.id).label == "（日志损坏）"
