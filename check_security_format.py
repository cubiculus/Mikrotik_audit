#!/usr/bin/env python3
"""Check RouterOS output format for security checks."""

from src.ssh_handler import SSHHandler
from src.config import RouterConfig

config = RouterConfig(
    router_ip='192.168.1.1',
    ssh_port=22,
    ssh_user='cubic-read',
    ssh_pass='XqqC3C78G3ASBdnpegwU'
)

ssh = SSHHandler(config)
ssh.connect()

print("=" * 70)
print("=== /ip ssh print ===")
print("=" * 70)
result = ssh.execute_command('/ip ssh print')
print(f"Exit: {result[0]}")
print(f"Output:\n{result[1]}")
print()

print("=" * 70)
print("=== /ip dns print ===")
print("=" * 70)
result = ssh.execute_command('/ip dns print')
print(f"Exit: {result[0]}")
print(f"Output:\n{result[1]}")
print()

print("=" * 70)
print("=== /ppp secret print ===")
print("=" * 70)
result = ssh.execute_command('/ppp secret print')
print(f"Exit: {result[0]}")
print(f"Output:\n{result[1]}")
print()

print("=" * 70)
print("=== /ppp profile print ===")
print("=" * 70)
result = ssh.execute_command('/ppp profile print')
print(f"Exit: {result[0]}")
print(f"Output:\n{result[1]}")
print()

print("=" * 70)
print("=== /ppp profile print detail ===")
print("=" * 70)
result = ssh.execute_command('/ppp profile print detail')
print(f"Exit: {result[0]}")
print(f"Output:\n{result[1]}")
print()

ssh.close()
