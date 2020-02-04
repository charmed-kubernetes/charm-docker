from unittest.mock import patch

from reactive import docker


def test_certificate_directory():
    """
    Assert CERTIFICATE_DIRECTORY is a string.
    """
    assert isinstance(docker.CERTIFICATE_DIRECTORY, str)


def test_fix_iptables_for_docker_1_13():
    """
    Assert correct parameters are called.
    """
    with patch('reactive.docker.check_call') as mock_cc:
        docker.fix_iptables_for_docker_1_13()

        assert mock_cc.assert_called_once_with(
            ['iptables', '-w', '300', '-P', 'FORWARD', 'ACCEPT']
        )


def test_install_from_archive_apt():
    """
    Assert correct parameters are called.
    """
    with patch('reactive.docker.apt_install') as mock_install:
        docker.install_from_archive_apt()

        assert mock_install.assert_called_once_with(['docker.io'], fatal=True)
