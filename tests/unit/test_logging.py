from __future__ import annotations

import logging

from ananke.logging import format_event, format_value, get_logger


def test_format_sorted_and_quoted():
    line = format_event("run_started", {"z": 1, "a": "two words", "item_key": "RENCI/x"})
    assert line == 'event=run_started a="two words" item_key=RENCI/x z=1'


def test_format_values():
    assert format_value(None) == "null"
    assert format_value(True) == "true"
    assert format_value("") == '""'
    assert format_value('a"b') == '"a\\"b"'
    assert format_value("line\nbreak") == '"line\\nbreak"'
    assert format_value([1, 2]) == "[1,2]"


def test_logger_emits_one_line_with_passthrough(caplog):
    log = get_logger("ananke.test")
    with caplog.at_level(logging.INFO, logger="ananke.test"):
        log.info("dispatch", run_id="r-1", item_key="k1", attempt=2)
    rec = caplog.records[-1]
    assert rec.getMessage() == "event=dispatch attempt=2 item_key=k1 run_id=r-1"
    assert "\n" not in rec.getMessage()
    assert rec.item_key == "k1" and rec.run_id == "r-1"
    assert rec.ananke_fields == {"run_id": "r-1", "item_key": "k1", "attempt": 2}


def test_bind_context(caplog):
    log = get_logger("ananke.test").bind(run_id="r-9")
    with caplog.at_level(logging.WARNING, logger="ananke.test"):
        log.warning("stalled", idle_s=601)
        log.info("ignored_below_level")
    assert [r.getMessage() for r in caplog.records] == ["event=stalled idle_s=601 run_id=r-9"]
