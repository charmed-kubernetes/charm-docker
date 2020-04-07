from unittest import TestCase
from unittest.mock import patch

from reactive import docker


class TestDocker(TestCase):
    """
    Docker charm tests.
    """
    def tearDown(self):
        docker.status_set.reset_mock()

    @staticmethod
    def test_install():
        """
        Assert usermod is called during install.
        """
        with patch('reactive.docker.check_call') as mock_cc:
            with patch('reactive.docker.open'):
                with patch('reactive.docker.reload_system_daemons'):
                    with patch('reactive.docker.determine_apt_source') as apt:
                        apt.return_value = 'apt'
                        docker.install()
                        mock_cc.assert_called_once_with(
                            ['usermod', '-aG', 'docker', 'ubuntu']
                        )

    @staticmethod
    def test_certificate_directory():
        """
        Assert CERTIFICATE_DIRECTORY is a string.
        """
        assert isinstance(docker.CERTIFICATE_DIRECTORY, str)

    @staticmethod
    def test_fix_iptables_for_docker_1_13():
        """
        Assert correct parameters are called.
        """
        with patch('reactive.docker.check_call') as mock_cc:
            docker.fix_iptables_for_docker_1_13()
            mock_cc.assert_called_once_with(
                ['iptables', '-w', '300', '-P', 'FORWARD', 'ACCEPT']
            )

    @staticmethod
    def test_install_from_archive_apt():
        """
        Assert correct parameters are called.
        """
        with patch('reactive.docker.apt_install') as mock_install:
            docker.install_from_archive_apt()
            mock_install.assert_called_once_with(['docker.io'], fatal=True)

    @staticmethod
    def test_probe_runtime_availability():
        """
        Assert correct parameters are called.
        """
        with patch('reactive.docker.check_call') as mock_cc:
            docker._probe_runtime_availability()
            mock_cc.assert_called_once_with(['docker', 'info'])

    def test_validate_config(self):
        """
        Assert validate raises bad config.
        """
        valid_config = {'no_proxy': 'test'}
        docker.validate_config(valid_config)

        invalid_config = {
            'no_proxy': 'a' * 2049
        }
        self.assertRaises(
            docker.ConfigError,
            docker.validate_config,
            invalid_config
        )

    def test_series_upgrade(self):
        assert docker.status_set.call_count == 0
        docker.pre_series_upgrade()
        assert docker.status_set.call_count == 1
