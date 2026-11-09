import ctypes
import errno
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
GUARD = HERE / "build" / "socket-guard"


def listen(family, host, port=0):
    server = socket.socket(family, socket.SOCK_STREAM)
    if family == socket.AF_INET6:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    server.bind((host, port))
    server.listen()
    return server


def require_denied(operation):
    try:
        operation()
    except OSError as error:
        if error.errno in (errno.EPERM, errno.EACCES):
            return
        raise
    raise AssertionError("The kernel did not deny a forbidden socket operation")


def check_interface_discovery(hidden):
    libc = ctypes.CDLL(None, use_errno=True)
    interfaces = ctypes.c_void_p()
    result = libc.getifaddrs(ctypes.byref(interfaces))
    if result == 0:
        libc.freeifaddrs(interfaces)
    if hidden:
        assert result == -1 and ctypes.get_errno() == errno.EPERM
        require_denied(lambda: socket.socket(socket.AF_ROUTE, socket.SOCK_RAW))
    else:
        assert result == 0
        with socket.socket(socket.AF_ROUTE, socket.SOCK_RAW):
            pass
    assert socket.gethostname()


def probe(port, other_port, inherited_fd, directory, family_mode, hidden, nested):
    for name, family, host in (("ipv4", socket.AF_INET, "127.0.0.1"),
                               ("ipv6", socket.AF_INET6, "::1")):
        with socket.socket(family, socket.SOCK_STREAM) as stream:
            if family_mode in ("dual", name):
                stream.connect((host, port))
                stream.sendall(b"proxy-only")
            else:
                require_denied(lambda: stream.connect((host, port)))
        with socket.socket(family, socket.SOCK_STREAM) as stream:
            require_denied(lambda: stream.connect((host, other_port)))
            require_denied(lambda: stream.bind((host, 0)))
        with socket.socket(family, socket.SOCK_DGRAM) as datagram:
            require_denied(lambda: datagram.sendto(b"dns", (host, port)))

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as stream:
        require_denied(lambda: stream.connect(("::ffff:127.0.0.1", port)))

    for path in (directory / "local.sock", Path("/var/run/mDNSResponder")):
        if path.exists():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as local:
                require_denied(lambda: local.connect(str(path)))

    try:
        os.fstat(inherited_fd)
    except OSError as error:
        assert error.errno == errno.EBADF
    else:
        raise AssertionError("The launcher left the inherited socket open")

    assert Path.cwd() == directory.resolve()
    file = directory / "native.txt"
    file.write_text("native file access", encoding="utf-8")
    assert Path("native.txt").read_text(encoding="utf-8") == "native file access"
    assert os.path.samefile(file, "native.txt")
    check_interface_discovery(hidden)

    if not nested:
        subprocess.run([sys.executable, __file__, *sys.argv[1:], "nested"], check=True)


def run_test():
    with (
        listen(socket.AF_INET, "127.0.0.1") as v4,
        listen(socket.AF_INET6, "::1", v4.getsockname()[1]) as v6,
        listen(socket.AF_INET, "127.0.0.1") as blocked_v4,
        listen(socket.AF_INET6, "::1", blocked_v4.getsockname()[1]),
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as local,
        tempfile.TemporaryDirectory(prefix="socket-guard-", dir="/tmp") as temp,
    ):
        directory = Path(temp).resolve()
        local.bind(str(directory / "local.sock"))
        local.listen()
        port = str(v4.getsockname()[1])
        for mode, hidden in (("dual", False), ("ipv4", False), ("ipv6", False),
                             ("ipv4", True)):
            options = [] if mode == "dual" else ["--" + mode]
            if hidden:
                options.append("--hide-interfaces")
            subprocess.run(
                [GUARD, *options, port, sys.executable, __file__, port,
                 str(blocked_v4.getsockname()[1]), str(blocked_v4.fileno()),
                 str(directory), mode, str(int(hidden))],
                cwd=directory, pass_fds=(blocked_v4.fileno(),), check=True, timeout=15,
            )
            for name, server in (("ipv4", v4), ("ipv6", v6)):
                if mode not in ("dual", name):
                    continue
                server.settimeout(1)
                for _ in range(2):
                    connection, _ = server.accept()
                    with connection:
                        connection.settimeout(1)
                        with connection.makefile("rb") as payload:
                            assert payload.read() == b"proxy-only"
        result = subprocess.run(
            [GUARD, port, "/bin/sh", "-c", "exit 42"],
            check=False, timeout=5,
        )
        assert result.returncode == 42
        result = subprocess.run(
            [GUARD, port, "/usr/bin/true"], stdin=v4,
            check=False, capture_output=True, timeout=5,
        )
        assert result.returncode == 125
        assert b"unsafe inherited descriptors" in result.stderr
        with tempfile.TemporaryFile() as inherited:
            inherited.write(b"native inherited file")
            inherited.seek(0)
            subprocess.run([GUARD, port, sys.executable, "-c",
                "import os,sys; fd=int(sys.argv[1]); assert os.read(fd,6)==b'native'; os.write(fd,b' file')",
                str(inherited.fileno())], pass_fds=(inherited.fileno(),), check=True, timeout=5)
            assert inherited.tell() == 11
            inherited.seek(0)
            assert inherited.read() == b"native filerited file"

    print("Socket guard fixture passed")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        probe(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4]),
              sys.argv[5], sys.argv[6] == "1", len(sys.argv) > 7)
    else:
        run_test()
