import logging
import pytest


log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    bundle = ops_test.render_bundle(
        "tests/data/bundle.yaml", docker_charm=await ops_test.build_charm(".")
    )

    await ops_test.model.deploy(bundle)
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)
