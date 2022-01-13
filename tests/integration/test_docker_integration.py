import asyncio
import logging
import pytest
import time
import shlex


log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    log.info("Build Charm...")
    charm = await ops_test.build_charm(".")

    log.info("Build Bundle...")
    bundle = ops_test.render_bundle("tests/data/bundle.yaml", docker_charm=charm)

    log.info("Deploy Bundle...")
    model = ops_test.model_full_name
    cmd = f"juju deploy -m {model} {bundle}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"

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
