# Charm for Docker

This subordinate charm deploys the [Docker](http://docker.com) engine within
a running Juju charm application. Docker is an open platform for developers
and sysadmins to build, ship, and run distributed applications in containers.

Docker containers wrap a piece of software in a complete file system that 
contains everything needed to run an application on a server.

Docker focuses on distributing applications as containers that can be quickly 
assembled from components that are run the same on different servers without 
environmental dependencies. This eliminates the friction between development, 
QA, and production environments.

# States

The following states are set by this subordinate:

* `endpoint.{relation name}.available`

  This state is set when docker is available for use.


## Using the Docker subordinate charm

The Docker subordinate charm is to be used with principal
charms that need a container runtime.  To use, we deploy
the Docker subordinate charm and then relate it to the 
principal charm.

```
juju deploy docker-suborinate
juju add-relation docker [principal charm]
```

## Scale out Usage

This charm will automatically scale out with the
principal charm.

# Configuration

See [config.yaml](config.yaml) for
list of configuration options.

## Docker Compose

This charm also installs the 'docker-compose' python package using pip. So
once the charm has finished installing you have the ability to use [Docker
Compose](https://docs.docker.com/compose/) functionality such as control files,
and logging.

# Contact Information

This charm is available at <https://jujucharms.com/docker> and contains the 
open source operations code to deploy on all public clouds in the Juju 
ecosystem.

## Docker links

  - The [Docker homepage](https://www.docker.com/)
  - Docker [documentation](https://docs.docker.com/) for help with Docker 
  commands.
  - Docker [forums](https://forums.docker.com/) for community discussions.
  - Check the Docker [issue tracker](https://github.com/docker/docker/issues) 
  for bugs or problems with the Docker software.
  - The [charm-docker](https://github.com/juju-solutions/charm-docker) is
  the GitHub repository that contains the reactive code to build this Charm.
  - Check the charm-docker
  [issue-tracker](https://github.com/juju-solutions/charm-docker/issues) for
  bugs or problems related to the Charm.
