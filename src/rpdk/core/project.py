import json
import logging
import zipfile
from pathlib import Path
from tempfile import TemporaryFile
from uuid import uuid4

from botocore.exceptions import ClientError, WaiterError
from botocore.waiter import WaiterModel, create_waiter_with_client
from jinja2 import Environment, PackageLoader, select_autoescape
from jsonschema import Draft6Validator
from jsonschema.exceptions import ValidationError

from .boto_helpers import create_sdk_session
from .data_loaders import load_resource_spec, resource_json
from .exceptions import (
    DownstreamError,
    InternalError,
    InvalidProjectError,
    SpecValidationError,
)
from .plugin_registry import load_plugin
from .upload import Uploader

LOG = logging.getLogger(__name__)

SETTINGS_FILENAME = ".rpdk-config"
SCHEMA_UPLOAD_FILENAME = "schema.json"
OVERRIDES_FILENAME = "overrides.json"
ROLE_TEMPLATE_FILENAME = "resource-role.yaml"
TYPE_NAME_REGEX = "^[a-zA-Z0-9]{2,64}::[a-zA-Z0-9]{2,64}::[a-zA-Z0-9]{2,64}$"


LAMBDA_RUNTIMES = {
    "noexec",  # cannot be executed, schema only
    "java8",
    "go1.x",
    # python2.7 is EOL soon (2020-01-01)
    "python3.6",
    "python3.7",
    # dotnetcore1.0 is EOL soon (2019-06-27)
    "dotnetcore2.1",
    # nodejs8.10 is EOL soon (2019-12-??)
    "nodejs10.x",
}

SETTINGS_VALIDATOR = Draft6Validator(
    {
        "properties": {
            "language": {"type": "string"},
            "typeName": {"type": "string", "pattern": TYPE_NAME_REGEX},
            "runtime": {"type": "string", "enum": list(LAMBDA_RUNTIMES)},
            "entrypoint": {"type": ["string", "null"]},
            "testEntrypoint": {"type": ["string", "null"]},
            "settings": {"type": "object"},
        },
        "required": ["language", "typeName", "runtime", "entrypoint"],
        "additionalProperties": False,
    }
)


class Project:  # pylint: disable=too-many-instance-attributes
    def __init__(self, overwrite_enabled=False, root=None):
        self.overwrite_enabled = overwrite_enabled
        self.root = Path(root) if root else Path.cwd()
        self.settings_path = self.root / SETTINGS_FILENAME
        self.type_info = None
        self._plugin = None
        self.settings = None
        self.schema = None
        self.runtime = "noexec"
        self.entrypoint = None
        self.test_entrypoint = None

        self.env = Environment(
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
            loader=PackageLoader(__name__, "templates/"),
            autoescape=select_autoescape(["html", "htm", "xml"]),
        )

        LOG.debug("Root directory: %s", self.root)

    @property
    def type_name(self):
        return "::".join(self.type_info)

    @type_name.setter
    def type_name(self, value):
        self.type_info = tuple(value.split("::"))

    @property
    def hypenated_name(self):
        return "-".join(self.type_info).lower()

    @property
    def schema_filename(self):
        return "{}.json".format(self.hypenated_name)

    @property
    def schema_path(self):
        return self.root / self.schema_filename

    @property
    def overrides_path(self):
        return self.root / OVERRIDES_FILENAME

    @staticmethod
    def _raise_invalid_project(msg, e):
        LOG.debug(msg, exc_info=e)
        raise InvalidProjectError(msg) from e

    def load_settings(self):
        LOG.debug("Loading project file '%s'", self.settings_path)
        try:
            with self.settings_path.open("r", encoding="utf-8") as f:
                raw_settings = json.load(f)
        except json.JSONDecodeError as e:
            self._raise_invalid_project(
                "Project file '{}' is invalid".format(self.settings_path), e
            )

        try:
            SETTINGS_VALIDATOR.validate(raw_settings)
        except ValidationError as e:
            self._raise_invalid_project(
                "Project file '{}' is invalid".format(self.settings_path), e
            )

        self.type_name = raw_settings["typeName"]
        self.runtime = raw_settings["runtime"]
        self.entrypoint = raw_settings["entrypoint"]
        self.test_entrypoint = raw_settings["testEntrypoint"]
        self._plugin = load_plugin(raw_settings["language"])
        self.settings = raw_settings.get("settings", {})

    def _write_example_schema(self):
        self.schema = resource_json(
            __name__, "data/examples/resource/initech.tps.report.v1.json"
        )
        self.schema["typeName"] = self.type_name

        def _write(f):
            json.dump(self.schema, f, indent=4)
            f.write("\n")

        self.safewrite(self.schema_path, _write)

    def _write_settings(self, language):
        if self.runtime not in LAMBDA_RUNTIMES:
            LOG.critical(
                "Plugin returned invalid runtime: %s (%s)", self.runtime, language
            )
            raise InternalError("Internal error (Plugin returned invalid runtime)")

        def _write(f):
            json.dump(
                {
                    "typeName": self.type_name,
                    "language": language,
                    "runtime": self.runtime,
                    "entrypoint": self.entrypoint,
                    "testEntrypoint": self.test_entrypoint,
                    "settings": self.settings,
                },
                f,
                indent=4,
            )
            f.write("\n")

        self.overwrite(self.settings_path, _write)

    def init(self, type_name, language):
        self.type_name = type_name
        self._plugin = load_plugin(language)
        self.settings = {}

        self._write_example_schema()
        self._plugin.init(self)
        self._write_settings(language)

    def load_schema(self):
        if not self.type_info:
            msg = "Internal error (Must load settings first)"
            LOG.critical(msg)
            raise InternalError(msg)

        with self.schema_path.open("r", encoding="utf-8") as f:
            self.schema = load_resource_spec(f)

    @staticmethod
    def overwrite(path, contents):
        LOG.debug("Overwriting '%s'", path)
        with path.open("w", encoding="utf-8") as f:
            if callable(contents):
                contents(f)
            else:
                f.write(contents)

    def safewrite(self, path, contents):
        if self.overwrite_enabled:
            self.overwrite(path, contents)
        else:
            try:
                with path.open("x", encoding="utf-8") as f:
                    if callable(contents):
                        contents(f)
                    else:
                        f.write(contents)
            except FileExistsError:
                LOG.warning("File already exists, not overwriting '%s'", path)

    def generate(self):
        # generate template for IAM role assumed by cloudformation
        # to provision resources if schema has handlers defined
        if "handlers" in self.schema:
            template = self.env.get_template("resource-role.yml")
            permission = "Allow"
            path = self.root / ROLE_TEMPLATE_FILENAME
            LOG.debug("Writing Resource Role CloudFormation template: %s", path)
            actions = {
                action
                for handler in self.schema["handlers"].values()
                for action in handler.get("permissions", [])
            }
            # gets rid of any empty string actions.
            # Empty strings cannot be specified as an action in an IAM statement
            actions.discard("")
            # Check if handler has actions
            if not actions:
                actions.add("*")
                permission = "Deny"

            contents = template.render(
                type_name=self.hypenated_name, actions=actions, permission=permission
            )
            self.overwrite(path, contents)

        return self._plugin.generate(self)

    def load(self):
        try:
            self.load_settings()
        except FileNotFoundError as e:
            self._raise_invalid_project(
                "Project file not found. Have you run 'init'?", e
            )

        LOG.info("Validating your resource specification...")
        try:
            self.load_schema()
        except FileNotFoundError as e:
            self._raise_invalid_project("Resource specification not found.", e)
        except SpecValidationError as e:
            msg = "Resource specification is invalid: " + str(e)
            self._raise_invalid_project(msg, e)

    def submit(
        self, dry_run, endpoint_url, region_name, role_arn, use_role, set_default
    ):  # pylint: disable=too-many-arguments
        # if it's a dry run, keep the file; otherwise can delete after upload
        if dry_run:
            path = Path("{}.zip".format(self.hypenated_name))
            context_mgr = path.open("wb")
        else:
            context_mgr = TemporaryFile("w+b")

        with context_mgr as f:
            # the default compression is ZIP_STORED, which helps with the
            # file-size check on upload
            with zipfile.ZipFile(f, mode="w") as zip_file:
                zip_file.write(self.schema_path, SCHEMA_UPLOAD_FILENAME)
                zip_file.write(self.settings_path, SETTINGS_FILENAME)
                try:
                    zip_file.write(self.overrides_path, OVERRIDES_FILENAME)
                    LOG.debug("%s found. Writing to package.", OVERRIDES_FILENAME)
                except FileNotFoundError:
                    LOG.debug(
                        "%s not found. Not writing to package.", OVERRIDES_FILENAME
                    )
                self._plugin.package(self, zip_file)

            if dry_run:
                LOG.error("Dry run complete: %s", path.resolve())
            else:
                f.seek(0)
                self._upload(
                    f, endpoint_url, region_name, role_arn, use_role, set_default
                )

    def _upload(
        self, fileobj, endpoint_url, region_name, role_arn, use_role, set_default
    ):  # pylint: disable=too-many-arguments, too-many-locals
        LOG.debug("Packaging complete, uploading...")
        session = create_sdk_session(region_name)
        cfn_client = session.client("cloudformation", endpoint_url=endpoint_url)
        s3_client = session.client("s3")
        uploader = Uploader(cfn_client, s3_client)
        if use_role and not role_arn and "handlers" in self.schema:
            LOG.debug("Creating execution role for provider to use")
            role_arn = uploader.create_or_update_role(
                self.root / ROLE_TEMPLATE_FILENAME, self.hypenated_name
            )

        s3_url = uploader.upload(self.hypenated_name, fileobj)
        LOG.debug("Got S3 URL: %s", s3_url)
        log_delivery_role = uploader.get_log_delivery_role_arn()
        LOG.debug("Got Log Role: %s", log_delivery_role)
        kwargs = {
            "Type": "RESOURCE",
            "TypeName": self.type_name,
            "SchemaHandlerPackage": s3_url,
            "ClientRequestToken": str(uuid4()),
            "LoggingConfig": {
                "LogRoleArn": log_delivery_role,
                "LogGroupName": "{}-logs".format(self.hypenated_name),
            },
        }
        if role_arn and use_role:
            kwargs["ExecutionRoleArn"] = role_arn

        try:
            response = cfn_client.register_type(**kwargs)

        except ClientError as e:
            LOG.debug("Registering type resulted in unknown ClientError", exc_info=e)
            raise DownstreamError("Unknown CloudFormation error") from e
        else:
            self._wait_for_registration(
                cfn_client, response["RegistrationToken"], set_default
            )

    @staticmethod
    def _wait_for_registration(cfn_client, registration_token, set_default):
        # temporarily creating waiter inline
        # until the SDK releases and we can use get_waiter
        waiter_config = {
            "version": 2,
            "waiters": {
                "TypeRegistrationComplete": {
                    "delay": 5,
                    "operation": "DescribeTypeRegistration",
                    "maxAttempts": 200,
                    "description": "Wait until type registration is COMPLETE.",
                    "acceptors": [
                        {
                            "argument": "ProgressStatus",
                            "expected": "COMPLETE",
                            "matcher": "path",
                            "state": "success",
                        },
                        {
                            "argument": "ProgressStatus",
                            "expected": "FAILED",
                            "matcher": "path",
                            "state": "failure",
                        },
                    ],
                }
            },
        }
        registration_waiter = create_waiter_with_client(
            "TypeRegistrationComplete", WaiterModel(waiter_config), cfn_client
        )
        # registration_waiter = cfn_client.get_waiter("TypeRegistrationComplete")
        try:
            LOG.warning(
                "Successfully submitted type. "
                "Waiting for registration with token '%s' to complete.",
                registration_token,
            )
            registration_waiter.wait(RegistrationToken=registration_token)
        except WaiterError as e:
            LOG.warning(
                "Failed to register the type with registration token '%s'.",
                registration_token,
            )
            try:
                response = cfn_client.describe_type_registration(
                    RegistrationToken=registration_token
                )
            except ClientError as describe_error:
                LOG.debug(
                    "Describing type registration resulted in unknown ClientError",
                    exc_info=e,
                )
                raise DownstreamError(
                    "Error describing type registration"
                ) from describe_error
            LOG.warning(
                "Please see response for additional information: '%s'", response
            )
            raise DownstreamError("Type registration error") from e
        LOG.warning("Registration complete.")
        response = cfn_client.describe_type_registration(
            RegistrationToken=registration_token
        )
        LOG.warning(response)
        if set_default:
            arn = response["TypeVersionArn"]
            try:
                cfn_client.set_type_default_version(Arn=arn)
            except ClientError as e:
                LOG.debug(
                    "Setting default version resulted in unknown ClientError",
                    exc_info=e,
                )
                raise DownstreamError("Error setting default version") from e
            LOG.warning("Set default version to '%s", arn)
