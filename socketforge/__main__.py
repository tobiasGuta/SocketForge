import argparse
import sys

from . import VERSION


def main():
    parser = argparse.ArgumentParser(description="Explore local TCP and UDP sockets.")
    parser.add_argument(
        "--demo", action="store_true", help="show fictional socket data"
    )
    parser.add_argument("--version", action="version", version=f"SocketForge {VERSION}")
    args = parser.parse_args()

    try:
        from .window import SocketForge
    except (ImportError, ValueError) as error:
        parser.exit(
            1,
            f"SocketForge requires GTK4, Libadwaita, PyGObject and psutil. {error}\n"
            "On Fedora: sudo dnf install gtk4 libadwaita python3-gobject python3-psutil\n",
        )
    return SocketForge(demo=args.demo).run([sys.argv[0]])


if __name__ == "__main__":
    raise SystemExit(main())
