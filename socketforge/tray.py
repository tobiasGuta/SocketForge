"""Publish the desktop tray icon and menu over the session bus."""

from pathlib import Path

from gi.repository import Gio, GLib

from . import APP_ID

WATCHER = "org.kde.StatusNotifierWatcher"
ITEM = "org.kde.StatusNotifierItem"
MENU = "com.canonical.dbusmenu"
ITEM_PATH = "/SocketForge/StatusNotifierItem"
MENU_PATH = "/SocketForge/TrayMenu"

ITEM_XML = f"""
<node><interface name="{ITEM}">
  <property name="Category" type="s" access="read"/>
  <property name="Id" type="s" access="read"/>
  <property name="Title" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="IconName" type="s" access="read"/>
  <property name="IconThemePath" type="s" access="read"/>
  <property name="Menu" type="o" access="read"/>
  <property name="ItemIsMenu" type="b" access="read"/>
  <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
  <method name="Activate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
  <method name="SecondaryActivate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
</interface></node>
"""

MENU_XML = f"""
<node><interface name="{MENU}">
  <property name="Version" type="u" access="read"/>
  <property name="TextDirection" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="IconThemePath" type="as" access="read"/>
  <method name="GetLayout">
    <arg type="i" direction="in"/><arg type="i" direction="in"/><arg type="as" direction="in"/>
    <arg type="u" direction="out"/><arg type="(ia{{sv}}av)" direction="out"/>
  </method>
  <method name="GetGroupProperties">
    <arg type="ai" direction="in"/><arg type="as" direction="in"/><arg type="a(ia{{sv}})" direction="out"/>
  </method>
  <method name="GetProperty">
    <arg type="i" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="out"/>
  </method>
  <method name="Event">
    <arg type="i" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="in"/><arg type="u" direction="in"/>
  </method>
  <method name="AboutToShow"><arg type="i" direction="in"/><arg type="b" direction="out"/></method>
  <signal name="LayoutUpdated"><arg type="u"/><arg type="i"/></signal>
</interface></node>
"""


class Tray:
    def __init__(self, application, bus):
        self.application = application
        self.bus = bus
        self.menu_nodes = {}
        self.actions = {}
        self.revision = 1
        self.watcher_owner = None
        self.registered = False
        self.update()
        self.exports = [
            bus.register_object(
                path,
                Gio.DBusNodeInfo.new_for_xml(xml).interfaces[0],
                method,
                self._property,
                None,
            )
            for path, xml, method in (
                (ITEM_PATH, ITEM_XML, self._item_method),
                (MENU_PATH, MENU_XML, self._menu_method),
            )
        ]
        self.watch = Gio.bus_watch_name_on_connection(
            bus,
            WATCHER,
            Gio.BusNameWatcherFlags.NONE,
            self._appeared,
            self._vanished,
        )

    def _appeared(self, bus, name, owner):
        self.watcher_owner = owner
        bus.call(
            name,
            "/StatusNotifierWatcher",
            WATCHER,
            "RegisterStatusNotifierItem",
            GLib.Variant("(s)", (ITEM_PATH,)),
            None,
            Gio.DBusCallFlags.NONE,
            3000,
            None,
            self._registered,
            owner,
        )

    def _registered(self, bus, result, owner):
        try:
            bus.call_finish(result)
        except GLib.Error:
            return
        if self.watcher_owner == owner:
            self.registered = True

    def _vanished(self, *_):
        self.watcher_owner = None
        self.registered = False

    def close(self):
        self.watcher_owner = None
        self.registered = False
        Gio.bus_unwatch_name(self.watch)
        for export in self.exports:
            self.bus.unregister_object(export)

    def _property(self, _bus, _sender, path, _interface, key):
        if path == ITEM_PATH:
            props = {
                "Category": ("s", "ApplicationStatus"),
                "Id": ("s", APP_ID),
                "Title": ("s", "SocketForge"),
                "Status": ("s", "Active"),
                "IconName": ("s", APP_ID),
                "IconThemePath": ("s", str(Path(__file__).with_name("assets"))),
                "Menu": ("o", MENU_PATH),
                "ItemIsMenu": ("b", False),
                "ToolTip": (
                    "(sa(iiay)ss)",
                    (APP_ID, [], "SocketForge", "Network monitor"),
                ),
            }
        else:
            props = {
                "Version": ("u", 3),
                "TextDirection": ("s", "ltr"),
                "Status": ("s", "normal"),
                "IconThemePath": ("as", []),
            }
        return GLib.Variant(*props[key])

    def _item_method(
        self, _bus, _sender, _path, _interface, _method, _params, invocation
    ):
        invocation.return_value(None)
        self.application.activate()

    def _toggle_snapshots(self):
        windows = self.application.get_windows()
        if windows:
            windows[0].activate_action("win.pause", None)

    def _open_alerts(self):
        self.application.activate()
        self.application.get_windows()[0].open_alert_id("")

    def update(self):
        windows = self.application.get_windows()
        window = windows[0] if windows else None
        items = {
            1: ("Open SocketForge", self.application.activate),
            2: ("Open Alerts", self._open_alerts),
            3: (
                "Resume socket snapshots"
                if window and window.paused
                else "Pause socket snapshots",
                self._toggle_snapshots,
            ),
            4: (
                "Quit SocketForge",
                lambda: self.application.activate_action("quit", None),
            ),
        }
        nodes = {
            0: {"children-display": GLib.Variant("s", "submenu")},
            **{
                key: {"label": GLib.Variant("s", value[0])}
                for key, value in items.items()
            },
        }
        if nodes == self.menu_nodes:
            return
        self.menu_nodes = nodes
        self.actions = {key: value[1] for key, value in items.items()}
        self.revision += 1
        self.bus.emit_signal(
            None,
            MENU_PATH,
            MENU,
            "LayoutUpdated",
            GLib.Variant("(ui)", (self.revision, 0)),
        )

    def _menu_method(
        self, _bus, _sender, _path, _interface, method, params, invocation
    ):
        args = params.unpack()
        if method == "GetLayout":
            root, depth, names = args
            if root not in self.menu_nodes:
                invocation.return_dbus_error(f"{MENU}.UnknownItem", "Unknown menu item")
                return
            children = (
                [
                    GLib.Variant(
                        "(ia{sv}av)", (key, self._menu_properties(key, names), [])
                    )
                    for key in self.actions
                ]
                if root == 0 and depth != 0
                else []
            )
            result = GLib.Variant(
                "(u(ia{sv}av))",
                (self.revision, (root, self._menu_properties(root, names), children)),
            )
        elif method == "GetGroupProperties":
            ids, names = args
            result = GLib.Variant(
                "(a(ia{sv}))",
                (
                    [
                        (key, self._menu_properties(key, names))
                        for key in ids or self.menu_nodes
                        if key in self.menu_nodes
                    ],
                ),
            )
        elif method == "GetProperty":
            key, name = args
            value = self.menu_nodes.get(key, {}).get(name)
            if value is None:
                invocation.return_dbus_error(
                    f"{MENU}.UnknownProperty", "Unknown menu property"
                )
                return
            result = GLib.Variant("(v)", (value,))
        elif method == "AboutToShow":
            result = GLib.Variant("(b)", (False,))
        else:
            key, event, *_ = args
            invocation.return_value(None)
            if event == "clicked" and key in self.actions:
                self.actions[key]()
            return
        invocation.return_value(result)

    def _menu_properties(self, key, names):
        return {
            name: value
            for name, value in self.menu_nodes[key].items()
            if not names or name in names
        }
