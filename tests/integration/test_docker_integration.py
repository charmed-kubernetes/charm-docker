import asyncio
import logging
import pytest
import time


log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    bundle = ops_test.render_bundle(
        "tests/data/bundle.yaml", docker_charm=await ops_test.build_charm(".")
    )

    await ops_test.model.deploy(bundle)
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)


async def test_docker_opts(ops_test):
    app = ops_test.model.applications["docker"]
    await app.set_config({"docker-opts": "--default-ulimit=memlock=-1:-1"})

    deadline = time.time() + 60 * 60
    while time.time() < deadline:
        actions = await asyncio.gather(
            *[unit.run("ps --no-headers -C dockerd -o args") for unit in app.units]
        )
        if all(
            "--default-ulimit=memlock=-1:-1" in action.results["Stdout"]
            for action in actions
        ):
            break
        await asyncio.sleep(10)
    else:
        pytest.fail("Timed out waiting for docker opts")

    await app.set_config({"docker-opts": ""})
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)
