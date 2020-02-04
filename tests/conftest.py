import os
import sys
from unittest.mock import MagicMock

# mock dependencies which we don't care about covering in our tests
ch = MagicMock()
sys.modules['charmhelpers'] = ch
sys.modules['charmhelpers.core'] = ch.core
sys.modules['charmhelpers.core.host'] = ch.core.host
sys.modules['charmhelpers.core.hookenv'] = ch.core.hookenv
sys.modules['charmhelpers.core.templating'] = ch.core.templating
sys.modules['charmhelpers.fetch'] = ch.fetch
sys.modules['charmhelpers.contrib.charmsupport'] = ch.contrib.charmsupport

charms = MagicMock()
sys.modules['charms'] = charms
sys.modules['charms.docker'] = charms.docker
sys.modules['charms.layer'] = charms.layer
sys.modules['charms.layer.container_runtime_common'] = charms.layer.container_runtime_common
sys.modules['charms.reactive'] = charms.reactive
sys.modules['charms.reactive.helpers'] = charms.reactive.helpers

os.environ['JUJU_MODEL_UUID'] = 'test-1234'
