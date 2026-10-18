import json
import shutil
from pathlib import Path

import pytest

from forensictriage import synthetic
from forensictriage.report import build_report
from forensictriage.triage import CaseInputs, run_triage

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def synth_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("case") / "case"
    synthetic.generate(d)
    return d


@pytest.fixture(scope="session")
def truth(synth_dir):
    return json.loads((synth_dir / "ground_truth.json").read_text())


@pytest.fixture(scope="session")
def case_result(synth_dir, tmp_path_factory):
    out = tmp_path_factory.mktemp("out")
    return run_triage(CaseInputs.from_case_json(synth_dir / "case.json"), out)


@pytest.fixture(scope="session")
def report(case_result):
    return build_report(case_result)


@pytest.fixture
def fresh_case(synth_dir, tmp_path):
    """A private copy of the synthetic case that a test may damage."""
    dst = tmp_path / "case"
    shutil.copytree(synth_dir, dst)
    return dst
