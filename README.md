# SocketForge

SocketForge is a native GNOME app for investigating local network activity on Fedora. It shows current TCP and UDP sockets, records what changes during an investigation, and explains how local services are listening.

![SocketForge in GNOME dark mode showing fictional sockets](docs/demo.png)

## Run on Fedora

From the repository directory:

```sh
sudo dnf install gtk4 libadwaita python3-gobject python3-psutil
make install
socketforge
```

SocketForge appears in the GNOME app grid. The user install lives under `~/.local` and `make uninstall` removes the app and launcher. SocketForge requires GTK4 and Libadwaita 1.8 or newer. Use `python3 -m socketforge` to run from source, or add `--demo` to preview fictional sockets.

## Investigate a network change

1. Open **Timeline** and select **Start Session**. Wait for **Baseline captured**.
2. Start the application or service you want to observe. In **Listening Ports**, select a TCP listener to see its bind scope, systemd unit, matching Podman mapping for the current user, and firewalld interface zones where available.
3. Reproduce the issue or stop the service. Return to **Timeline** to search by process, address, or event type and inspect a socket after it disappears.
4. Select **Stop Session**. Sessions stay in memory by default. Select **Save locally** before recording to store the completed session on disk. Find it under **Saved Sessions** in the menu.

A session retains its most recent 2,000 events. Saving or opening history prunes sessions older than seven days and the database holds up to 20 sessions. **Clear Saved Sessions** deletes stored sessions. The history can include local and remote addresses, process names, and executable paths.

Snapshot events show when SocketForge first or last observed a socket. The app marks interruptions and establishes a fresh baseline. Sockets that come and go between two-second refreshes can be missed. Linux permissions and network namespaces limit which sockets and owners are visible. Listener context describes local configuration. Reachability also depends on rules, routing and the originating network.

Use **Ctrl+F** to focus search, **Ctrl+P** to pause or resume snapshots, and **Ctrl+R** to take a snapshot immediately. In **Live**, click a column header to sort. Open a TCP row for sampled RTT, retransmissions, byte totals, and rates when consecutive samples are available. The send rate measures acknowledged TCP data and the receive rate measures TCP data received. UDP and interface-wide traffic are outside these counters.

## Optional TCP event tracing

Fedora's precompiled `bpf-tcptracer` can report short-lived established TCP connections, including connect, accept, and close events. Install [`libbpf-tools`](https://packages.fedoraproject.org/pkgs/bcc/libbpf-tools/) if needed, then run the following in a terminal:

```sh
sudo -v
sudo -n /usr/bin/stdbuf -oL /usr/bin/bpf-tcptracer -u "$(id -u)" 2>&1 |
  socketforge --trace-stdin
```

Only the Fedora collector runs with elevated privileges. The command filters trace events to your UID, which can include sockets in other network namespaces. Start a Timeline session in the window opened by this command. Trace rows are labeled **Kernel trace** and timestamped when SocketForge reads them. They can appear alongside sampled observations of the same connection. The Timeline shows collector status and reports loss warnings from BCC or an overflowing input queue. Stop the pipeline with **Ctrl+C** in the terminal when finished. Kernel support and local security policy can prevent the collector from attaching. The regular launcher continues to provide snapshot monitoring.

## Test

```sh
python3 -m unittest discover -s tests -v
```
