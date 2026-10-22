"""Trained models are not in git, so a release never carries them: the check says what a retrained model changes and
whether this copy's packages can load it, before anyone copies it into the live system."""

from __future__ import annotations

import json

import joblib

from atdr.scripts import check_models


def _folders(tmp_path):
    source, here = tmp_path / "development-models", tmp_path / "live-models"
    source.mkdir()
    here.mkdir()
    joblib.dump({"trees": 10}, source / "same.joblib")
    joblib.dump({"trees": 10}, here / "same.joblib")
    joblib.dump({"trees": 20}, source / "retrained.joblib")
    joblib.dump({"trees": 10}, here / "retrained.joblib")
    joblib.dump({"trees": 5}, source / "added.joblib")
    (source / "model.card.json").write_text(json.dumps({"version": "mfu_behavior_v3"}), encoding="utf-8")
    (here / "model.card.json").write_text(json.dumps({"version": "mfu_behavior_v2"}), encoding="utf-8")
    (source / ".gitkeep").write_text("", encoding="utf-8")
    return source, here


def test_the_check_lists_what_a_retrained_model_changes_and_loads_each_new_file(tmp_path):
    source, here = _folders(tmp_path)

    report = check_models.compare_models(source, here)

    states = {entry["file"]: entry["state"] for entry in report["files"]}
    assert states == {"added.joblib": "new", "model.card.json": "different", "retrained.joblib": "different", "same.joblib": "same"}
    assert report["to_copy"] == ["added.joblib", "model.card.json", "retrained.joblib"] and report["ok"] is True
    loaded = {entry["file"]: entry.get("load_error", "not loaded") for entry in report["files"]}
    assert loaded["retrained.joblib"] is None and loaded["added.joblib"] is None and loaded["same.joblib"] == "not loaded"
    card = next(entry for entry in report["files"] if entry["file"] == "model.card.json")
    assert (card["version"], card["version_here"]) == ("mfu_behavior_v3", "mfu_behavior_v2")
    words = check_models.render(report)
    assert "model.card.json: different, version mfu_behavior_v3 (here: mfu_behavior_v2)" in words
    assert "retrained.joblib: different, loads here" in words and "3 file(s) to copy" in words


def test_a_model_this_copy_cannot_load_is_named_and_the_check_fails(tmp_path, monkeypatch, capsys):
    source, here = _folders(tmp_path)
    (source / "broken.joblib").write_bytes(b"not a model")
    monkeypatch.setattr(check_models, "HERE", here)

    assert check_models.main(["--from", str(source)]) == 1
    said = capsys.readouterr().out
    assert "broken.joblib: new, DOES NOT LOAD here" in said and "Do not copy these" in said


def test_nothing_new_is_said_plainly(tmp_path, monkeypatch, capsys):
    source, here = tmp_path / "a", tmp_path / "b"
    source.mkdir()
    here.mkdir()
    joblib.dump({"trees": 10}, source / "same.joblib")
    joblib.dump({"trees": 10}, here / "same.joblib")
    monkeypatch.setattr(check_models, "HERE", here)

    assert check_models.main(["--from", str(source)]) == 0
    assert "Nothing to install." in capsys.readouterr().out
