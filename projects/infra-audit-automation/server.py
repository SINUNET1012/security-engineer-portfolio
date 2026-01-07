from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import paramiko


@dataclass
class Server:
    """
    2026 주정통 점검용 SSH 유틸 클래스

    - 2025 ipynb 스타일 호환을 위해 `ssh()`는 기본적으로 paramiko stdout(파일 객체)을 반환합니다.
      예) `server.ssh(\"id\").read().decode().strip()`
    - 편의용으로 `ssh_str()`도 제공합니다.
    """

    ip: str
    os: str = ""
    sshId: str = ""
    sshPw: str = ""
    port: int = 22
    timeout: int = 10
    key_filename: Optional[str] = None

    _client: Optional[paramiko.SSHClient] = None

    def connect(self) -> None:
        if self._client is not None:
            return
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cli.connect(
            self.ip,
            port=self.port,
            username=self.sshId or None,
            password=self.sshPw or None,
            timeout=self.timeout,
            auth_timeout=self.timeout,
            banner_timeout=self.timeout,
            key_filename=self.key_filename,
        )
        self._client = cli

    def close(self) -> None:
        if self._client is None:
            return
        try:
            self._client.close()
        finally:
            self._client = None

    def ssh(self, cmd: str):
        """
        cmd 실행 후 stdout(파일 객체)을 반환합니다.
        """

        self.connect()
        assert self._client is not None
        _stdin, stdout, _stderr = self._client.exec_command(cmd)
        return stdout

    def ssh_str(self, cmd: str) -> str:
        """
        cmd 실행 stdout을 문자열로 반환합니다(utf-8 decode, strip).
        """

        out = self.ssh(cmd).read()
        try:
            return out.decode("utf-8", errors="replace").strip()
        except Exception:
            return str(out).strip()

    def detect_os(self) -> str:
        if self.os:
            return self.os
        text = self.ssh_str("cat /etc/os-release 2>/dev/null || true")
        for line in text.splitlines():
            if line.startswith("ID="):
                self.os = line.split("=", 1)[1].strip().strip('"').lower()
                return self.os
        self.os = "unknown"
        return self.os

    def __enter__(self) -> "Server":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False

