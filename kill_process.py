import argparse
import subprocess
import sys
import re

def find_pids_on_port(port: int) -> set[int]:
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True,
            text=True,
            check=True,
            shell=False
        )
    except Exception as e:
        print(f"Failed to run netstat: {e}")
        sys.exit(1)

    pids: set[int] = set()
    # 匹配本地地址包含 :<port> 的行，最后一列为 PID
    pattern = re.compile(rf"^(TCP|UDP)\s+\S*:{port}\b.*\s(\d+)\s*$", re.IGNORECASE)
    for line in result.stdout.splitlines():
        line = line.strip()
        m = pattern.search(line)
        if m:
            try:
                pids.add(int(m.group(2)))
            except ValueError:
                pass
    return pids

def kill_pid(pid: int) -> bool:
    try:
        proc = subprocess.run(
            ["taskkill", "/PID", str(pid), "/F"],
            capture_output=True,
            text=True,
            shell=False
        )
        if proc.returncode == 0:
            print(f"Killed PID {pid}")
            return True
        else:
            # 常见：进程不存在、权限不足等
            print(f"Failed to kill PID {pid}: {proc.stdout or proc.stderr}".strip())
            return False
    except Exception as e:
        print(f"Error killing PID {pid}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Kill processes listening/using a given port (Windows).")
    parser.add_argument("port", type=int, help="Port number, e.g., 6277")
    args = parser.parse_args()

    if not (1 <= args.port <= 65535):
        print("Invalid port. Must be in 1..65535")
        sys.exit(2)

    pids = find_pids_on_port(args.port)
    if not pids:
        print(f"No processes found using port {args.port}.")
        return

    print(f"Found PIDs on port {args.port}: {', '.join(map(str, sorted(pids)))}")
    success = True
    for pid in sorted(pids):
        ok = kill_pid(pid)
        success = success and ok

    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()