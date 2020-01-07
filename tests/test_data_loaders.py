# fixture and parameter have the same name
# pylint: disable=redefined-outer-name
# pylint: disable=import-outside-toplevel
import json
from contextlib import contextmanager
from io import BytesIO, StringIO
from pathlib import Path
from subprocess import check_output
from unittest.mock import ANY, create_autospec, patch

import jsonschema
import pytest
import yaml
from jsonschema.exceptions import RefResolutionError, ValidationError
from pytest_localserver.http import Request, Response, WSGIServer

from rpdk.core.data_loaders import (
    STDIN_NAME,
    get_file_base_uri,
    load_resource_spec,
    make_validator,
    resource_json,
    resource_stream,
    resource_yaml,
)
from rpdk.core.exceptions import InternalError, SpecValidationError
from rpdk.core.plugin_base import LanguagePlugin

BASEDIR = Path(__file__).parent  # tests/test_data_loaders.py -> tests/

# Lonely continuation byte is invalid
# https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
INVALID_UTF8 = b"\x80"

BASIC_SCHEMA = {
    "typeName": "AWS::FOO::BAR",
    "description": "test schema",
    "properties": {"foo": {"type": "string"}},
    "primaryIdentifier": ["/properties/foo"],
}


def json_s(obj):
    return StringIO(json.dumps(obj))


def test_load_resource_spec_invalid_json():
    with pytest.raises(SpecValidationError) as excinfo:
        load_resource_spec(StringIO('{"foo": "aaaaa}'))

    assert "line 1" in str(excinfo.value)
    assert "column 9" in str(excinfo.value)


def test_load_resource_spec_empty_is_invalid():
    with pytest.raises(SpecValidationError):
        load_resource_spec(StringIO(""))


def test_load_resource_spec_boolean_is_invalid():
    with pytest.raises(SpecValidationError):
        load_resource_spec(json_s(True))


def test_load_resource_spec_empty_object_is_invalid():
    with pytest.raises(SpecValidationError):
        load_resource_spec(json_s({}))


def json_files_params(path, glob="*.json"):
    return tuple(pytest.param(p, id=p.name) for p in path.glob(glob))


@pytest.mark.parametrize(
    "example", json_files_params(BASEDIR.parent / "examples" / "schema", "*-*-*.json")
)
def test_load_resource_spec_example_spec_is_valid(example):
    with example.open("r", encoding="utf-8") as f:
        assert load_resource_spec(f)


@pytest.mark.parametrize(
    "example", json_files_params(BASEDIR / "data" / "schema" / "valid")
)
def test_load_resource_spec_valid_snippets(example):
    with example.open("r", encoding="utf-8") as f:
        assert load_resource_spec(f)


@pytest.mark.parametrize(
    "example", json_files_params(BASEDIR / "data" / "schema" / "invalid")
)
def test_load_resource_spec_invalid_snippets(example):
    with example.open("r", encoding="utf-8") as f:
        with pytest.raises(SpecValidationError):
            load_resource_spec(f)


def test_load_resource_spec_remote_key_is_invalid():
    schema = {
        "typeName": "AWS::FOO::BAR",
        "description": "test schema",
        "properties": {"foo": {"type": "string"}},
        "primaryIdentifier": ["/properties/foo"],
        "remote": {},
    }
    with pytest.raises(SpecValidationError) as excinfo:
        load_resource_spec(json_s(schema))
    assert "remote" in str(excinfo.value)


def test_argparse_stdin_name():
    """By default, pytest messes with stdin and stdout, which prevents me from
    writing a test to check we have the right magic name that argparse uses
    for stdin. So I invoke a separate, pristine python process to check.
    """
    code = "; ".join(
        """import argparse
parser = argparse.ArgumentParser()
parser.add_argument("file", type=argparse.FileType("r"))
args = parser.parse_args(["-"])
print(args.file.name)
""".splitlines()
    )

    raw = check_output(["python3", "-c", code])
    result = raw.rstrip().decode("utf-8")  # remove trailing newline
    assert result == STDIN_NAME


def test_get_file_base_uri_file_object_no_name():
    f = json_s(BASIC_SCHEMA)
    assert not hasattr(f, "name")
    expected = (Path.cwd() / "-").resolve().as_uri()
    actual = get_file_base_uri(f)
    assert actual == expected


def test_load_resource_spec_file_object_stdin():
    f = json_s(BASIC_SCHEMA)
    f.name = STDIN_NAME
    expected = (Path.cwd() / "-").resolve().as_uri()
    actual = get_file_base_uri(f)
    assert actual == expected


def test_load_resource_spec_file_object_has_name(tmpdir):
    f = json_s(BASIC_SCHEMA)
    f.name = tmpdir.join("test.json")
    expected = Path(f.name).resolve().as_uri()
    actual = get_file_base_uri(f)
    assert actual == expected


def test_load_resource_spec_inliner_produced_invalid_schema():
    with patch("rpdk.core.data_loaders.RefInliner", autospec=True) as mock_inliner:
        mock_inliner.return_value.inline.return_value = {}
        with pytest.raises(InternalError) as excinfo:
            load_resource_spec(json_s(BASIC_SCHEMA))

    mock_inliner.assert_called_once_with(ANY, BASIC_SCHEMA)
    cause = excinfo.value.__cause__
    assert cause
    assert isinstance(cause, ValidationError)


def test_load_resource_spec_invalid_ref():
    copy = json.loads(json.dumps(BASIC_SCHEMA))
    copy["properties"]["foo"] = {"$ref": "#/bar"}
    with pytest.raises(SpecValidationError) as excinfo:
        load_resource_spec(json_s(copy))

    cause = excinfo.value.__cause__
    assert cause
    assert isinstance(cause, RefResolutionError)
    assert "bar" in str(cause)


@pytest.fixture
def plugin():
    mock_plugin = create_autospec(LanguagePlugin)
    mock_plugin.project_settings_defaults.return_value = resource_stream(
        __name__, "data/project_defaults.yaml"
    )
    mock_plugin.project_settings_schema.return_value = resource_json(
        __name__, "data/project_schema.json"
    )
    return mock_plugin


@contextmanager
def wsgi_serve(application):
    server = WSGIServer(application=application)
    try:
        server.start()
        yield server
    finally:
        server.stop()


def test_make_validator_handlers_time_out():
    from time import sleep

    @Request.application
    def application(request):  # pylint: disable=unused-argument
        sleep(3)
        return Response("true", mimetype="application/json")

    with wsgi_serve(application) as server:
        with pytest.raises(jsonschema.exceptions.RefResolutionError) as excinfo:
            validator = make_validator(
                {"$ref": server.url}, base_uri="http://localhost/", timeout=0.5
            )
            validator.validate(True)
    assert "Read timed out" in str(excinfo.value)


def mock_pkg_resource_stream(bytes_in, func=resource_stream):
    resource_name = "data/test.utf-8"
    target = "rpdk.core.data_loaders.pkg_resources.resource_stream"
    with patch(target, autospec=True, return_value=BytesIO(bytes_in)) as mock_stream:
        f = func(__name__, resource_name)
    mock_stream.assert_called_once_with(__name__, resource_name)
    return f


def test_resource_stream_decoding_valid():
    emoji_santa = "🎅"
    f = mock_pkg_resource_stream(emoji_santa.encode("utf-8"))
    assert f.read() == emoji_santa


def test_resource_stream_decoding_invalid():
    f = mock_pkg_resource_stream(INVALID_UTF8)

    # stream is lazily decoded
    with pytest.raises(UnicodeDecodeError) as excinfo:
        f.read()
    assert excinfo.value.encoding == "utf-8"
    assert excinfo.value.object == INVALID_UTF8


def test_resource_stream_universal_newlines():
    f = mock_pkg_resource_stream(b"Windows\r\n")
    assert f.read() == "Windows\n"


def test_resource_stream_with_statement():
    string = "Hello, World"
    with mock_pkg_resource_stream(string.encode("utf-8")) as f:
        assert f.read() == string

    with pytest.raises(ValueError) as excinfo:
        f.read()
    assert "I/O operation on closed file" in str(excinfo.value)


def test_resource_json():
    obj = {"foo": "bar"}
    encoded = json.dumps(obj).encode("utf-8")
    result = mock_pkg_resource_stream(encoded, func=resource_json)
    assert result == obj


def test_resource_yaml():
    obj = {"foo": "bar"}
    encoded = yaml.dump(obj).encode("utf-8")
    result = mock_pkg_resource_stream(encoded, func=resource_yaml)
    assert result == obj
