"""SAFE: fixed command list, user input never reaches the shell."""
import subprocess

NETWORK_TESTS = {
    "ping_local":  ["ping", "-c", "1", "127.0.0.1"],
    "ping_gateway": ["ping", "-c", "1", "192.168.1.1"],
}


def run_network_test(test_name: str) -> str:
    cmd = NETWORK_TESTS.get(test_name)
    if cmd is None:
        return "Unknown test"
    output = subprocess.check_output(cmd)
    return output.decode()
