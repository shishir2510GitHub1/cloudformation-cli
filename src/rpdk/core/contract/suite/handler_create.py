# fixture and parameter have the same name
# pylint: disable=redefined-outer-name
import logging

import pytest

# WARNING: contract tests should use fully qualified imports to avoid issues
# when being loaded by pytest
from rpdk.core.contract.interface import Action, OperationStatus
from rpdk.core.contract.suite.handler_commons import (
    test_create_failure_if_repeat_writeable_id,
    test_create_success,
    test_delete_success,
    test_list_success,
    test_read_success,
)

LOG = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def created_resource(resource_client):
    request = model = resource_client.generate_create_example()
    try:
        _status, response, _error = resource_client.call_and_assert(
            Action.CREATE, OperationStatus.SUCCESS, request
        )
        model = response["resourceModel"]
        yield model, request
    finally:
        resource_client.call_and_assert(Action.DELETE, OperationStatus.SUCCESS, model)


@pytest.mark.create
@pytest.mark.delete
def contract_create_delete(resource_client):
    requested_model = delete_model = resource_client.generate_create_example()
    try:
        response = test_create_success(resource_client, requested_model)
        # check response here
        delete_model = response["resourceModel"]
    finally:
        test_delete_success(resource_client, delete_model)


@pytest.mark.create
def contract_create_duplicate(created_resource, resource_client):
    _created_model, request = created_resource
    test_create_failure_if_repeat_writeable_id(resource_client, request)


@pytest.mark.create
@pytest.mark.read
def contract_create_read_success(created_resource, resource_client):
    created_model, _request = created_resource
    test_read_success(resource_client, created_model)


@pytest.mark.create
@pytest.mark.list
def contract_create_list_success(created_resource, resource_client):
    created_model, _request = created_resource
    models = test_list_success(resource_client, created_model)
    assert created_model in models
