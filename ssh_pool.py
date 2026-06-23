import paramiko
import threading
import logging
from typing import Optional
from config import settings

logger = logging.getLogger(__name__)


class SSHPool:
    """
    Maintains a single persistent SSH connection to pfSense.
    Thread-safe: uses a lock so multiple API requests don't conflict.
    Falls back to a fresh connection if the persistent one drops.
    """

    def __init__(self):
        self._client: Optional[paramiko.SSHClient] = None
        self._lock = threading.Lock()

    def _is_alive(self) -> bool:
        try:
            if self._client is None:
                return False
            transport = self._client.get_transport()
            return transport is not None and transport.is_active()
        except Exception:
            return False

    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            settings.PFSENSE_HOST,
            username=settings.PFSENSE_USER,
            password=settings.PFSENSE_PASS,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
        logger.info("SSH connection established to pfSense")
        return client

    def execute(self, command: str) -> tuple[str, str]:
        """
        Run a command on pfSense.
        Returns (stdout, stderr) as strings.
        Raises RuntimeError on failure.
        """
        with self._lock:
            if not self._is_alive():
                logger.info("SSH connection not active — reconnecting...")
                self._client = self._connect()

            try:
                _, stdout, stderr = self._client.exec_command(command, timeout=15, get_pty=False)
                out = stdout.read().decode(errors="replace")
                err = stderr.read().decode(errors="replace")
                return out, err
            except Exception as e:
                # Connection may have died mid-command — try once more
                logger.warning(f"Command failed ({e}), retrying with fresh connection...")
                self._client = self._connect()
                _, stdout, stderr = self._client.exec_command(command, timeout=15, get_pty=False)
                out = stdout.read().decode(errors="replace")
                err = stderr.read().decode(errors="replace")
                return out, err

    def close(self):
        if self._client:
            self._client.close()
            self._client = None


# Singleton used across the whole app
ssh_pool = SSHPool()
