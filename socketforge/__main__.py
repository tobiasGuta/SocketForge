import argparse
import sys

from . import VERSION


def main():
    parser = argparse.ArgumentParser(description="Explore local TCP and UDP sockets.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--demo", action="store_true", help="show fictional socket data")
    modes.add_argument(
        "--trace-stdin",
        action="store_true",
        help="read TCP trace events from stdin",
    )
    parser.add_argument("--version", action="version", version=f"SocketForge {VERSION}")
    args = parser.parse_args()

    try:
        from .trace import TraceInput
        from .window import SocketForge
    except (ImportError, ValueError) as error:
        parser.exit(
            1,
            f"SocketForge requires GTK4, Libadwaita, PyGObject and psutil. {error}\n"
            "On Fedora: sudo dnf install gtk4 libadwaita python3-gobject python3-psutil\n",
        )
    trace = TraceInput(sys.stdin) if args.trace_stdin else None
    return SocketForge(demo=args.demo, trace=trace).run([sys.argv[0]])


if __name__ == "__main__":
    raise SystemExit(main())
