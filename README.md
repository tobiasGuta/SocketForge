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

## Activity and alerts

**Activity** records observations while SocketForge runs, including its first snapshot, later socket changes, trace events, and logged hits from SocketForge firewall rules. Filter by Outbound, Inbound, Listening, Blocked, or Unknown. The button next to the filter groups the results by app. TCP connect and accept events supply direction. Snapshot-only sockets usually have unknown direction. The Activity view retains up to 2,000 rows and Alerts retains up to 300 entries for the current run. Use Timeline with **Save locally** to keep an investigation.

**Alerts** shows new non-loopback TCP listeners observed after the baseline, first accepts for watched services, new observed destinations for watched apps, and the first logged hit on a SocketForge rule. Desktop notifications start off. You can enable them, pause them for one hour, or mute a rule for a specific app from its alert details. These controls affect banners. App watches expire after 15 minutes. **Keep monitoring after closing** keeps the app running while signed in. Use **Quit SocketForge** from the menu to stop it.

In a socket’s details, **Inspect IP** classifies local and special-use addresses offline. **Look Up IP** sends the selected public address to its RDAP registry, RIPEstat, and your DNS resolver. It displays registration, announced prefix and ASN, reverse DNS, and an estimated country when available. Results are cached in memory. A prefix links to retained observations grouped by app. An address can belong to shared infrastructure, and the estimated location can vary from the server handling a connection.

## Temporary firewall blocks

On a non-loopback listener, open the Firewall section and choose an active zone. On an observed TCP or UDP outbound event, choose a host-output policy. Confirm the exact address, port, protocol, and zone or policy shown. firewalld applies a 15-minute runtime rule and can ask for administrator authorization. The rule matches traffic from any app within its scope. Established connections can remain active. The **Temporary Firewall Blocks** menu and the confirmation toast provide Undo during the current run.

The Blocked filter shows rate-limited kernel journal records for SocketForge rules. Hit counts reflect entries that reached the journal. Other firewall denies are outside this view. Existing global logging settings are left alone. Journal read access is required to show hits.

Outbound blocking requires a firewalld policy with `HOST` as ingress. An administrator can install the empty example below if no suitable policy exists. Reloading firewalld replaces runtime configuration, including temporary rules.

```sh
sudo firewall-cmd --permanent --new-policy-from-file=data/socketforge-output.xml
sudo firewall-cmd --reload
```

## Optional host collectors

For broader host coverage, an administrator can install Fedora’s `libbpf-tools` and `conntrack-tools` packages, then opt in to either systemd collector from this repository:

```sh
sudo dnf install libbpf-tools conntrack-tools
sudo install -m 0644 data/socketforge-tcp.service data/socketforge-udp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now socketforge-tcp.service socketforge-udp.service
```

Disable them with `sudo systemctl disable --now socketforge-tcp.service socketforge-udp.service`. These services record connection metadata in the system journal, which can include other users’ traffic. The GNOME app reads the journal as your user and reports collector status. TCP tracing reports supported connect, accept and close events. UDP conntrack reports tracked flows in the host namespace and SocketForge groups them by endpoint. It can label direction when one endpoint matches a host address. UDP process ownership and byte counts may be unavailable. VPNs, NAT, network namespaces, journal limits, and collector gaps affect visibility. Sampled TCP byte counts remain available through the existing socket diagnostics.
