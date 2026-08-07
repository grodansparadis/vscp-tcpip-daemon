# vscp-tcpip-daemon
A central VSCP daemon that exports a VSCP tcp/ip link interface and handles level I and level II drivers.

## Windows service

The Windows daemon executable is `tcpip-vscpd.exe` and can run as a Windows service.

Run these commands from an elevated Command Prompt or PowerShell.

```bat
sc create tcpip-vscpd binPath= "C:\\path\\to\\tcpip-vscpd.exe" start= auto DisplayName= "VSCP TCP/IP Daemon"
sc start tcpip-vscpd
sc stop tcpip-vscpd
sc delete tcpip-vscpd
```

To run in console mode instead of service mode:

```bat
tcpip-vscpd.exe --console
```

## macOS service

On macOS, run the daemon as a `launchd` service.

Create `/Library/LaunchDaemons/org.vscp.tcpip-vscpd.plist` with the following content:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>org.vscp.tcpip-vscpd</string>

	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/sbin/tcpip-vscpd</string>
		<string>-c</string>
		<string>/usr/local/etc/vscp/vscpd.json</string>
	</array>

	<key>RunAtLoad</key>
	<true/>

	<key>KeepAlive</key>
	<true/>

	<key>StandardOutPath</key>
	<string>/var/log/tcpip-vscpd.log</string>

	<key>StandardErrorPath</key>
	<string>/var/log/tcpip-vscpd.err</string>
</dict>
</plist>
```

Load/start, stop/unload, and inspect status:

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/org.vscp.tcpip-vscpd.plist
sudo launchctl kickstart -k system/org.vscp.tcpip-vscpd
sudo launchctl print system/org.vscp.tcpip-vscpd
sudo launchctl bootout system /Library/LaunchDaemons/org.vscp.tcpip-vscpd.plist
```

To run in console mode instead of launchd:

```bash
tcpip-vscpd -s
```

## Unix installation step

When you run CMake install on Unix, the startup script is installed as:

```text
/etc/init.d/tcpip-vscpd
```

Example:

```bash
cmake -S . -B build
cmake --build build
sudo cmake --install build
```
