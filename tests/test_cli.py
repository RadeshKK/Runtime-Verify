import os
import shutil
import tempfile
import json
import pytest
from typer.testing import CliRunner
from runtimeverify.cli import app

runner = CliRunner()

@pytest.fixture
def temp_workspace():
    # Setup temporary directory for workspace testing
    temp_dir = tempfile.mkdtemp()
    orig_cwd = os.getcwd()
    os.chdir(temp_dir)
    yield temp_dir
    os.chdir(orig_cwd)
    shutil.rmtree(temp_dir)

def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "AI Runtime Verification Framework (verify)" in result.stdout

def test_cli_doctor():
    result = runner.invoke(app, ["doctor"])
    # May fail doctor checks, but CLI command itself runs successfully (exit code 0)
    assert result.exit_code == 0

def test_cli_init_and_train_and_inspect(temp_workspace):
    # 1. Test verify init
    result_init = runner.invoke(app, ["init"])
    assert result_init.exit_code == 0
    assert os.path.exists(".runtimeverify/config.yaml")
    assert os.path.exists(".runtimeverify/rules.json")

    # 2. Generate training data
    traces = [
        ["START", "READ", "WRITE", "COMMIT"],
        ["START", "READ", "WRITE", "COMMIT"]
    ]
    traces_file = "test_traces.json"
    with open(traces_file, "w") as f:
        json.dump(traces, f)

    # 3. Test verify train
    result_train = runner.invoke(app, ["train", traces_file, "-o", ".runtimeverify/models/test_model.json"])
    assert result_train.exit_code == 0
    assert os.path.exists(".runtimeverify/models/test_model.json")

    # 4. Test verify inspect
    result_inspect = runner.invoke(app, ["inspect", ".runtimeverify/models/test_model.json"])
    assert result_inspect.exit_code == 0
    assert "Model Details:" in result_inspect.stdout
    assert "READ" in result_inspect.stdout

    # 5. Test verify explain
    result_explain = runner.invoke(app, ["explain", "READ", "WRITE", "--model", ".runtimeverify/models/test_model.json"])
    assert result_explain.exit_code == 0
    assert "Transition Explanation" in result_explain.stdout
