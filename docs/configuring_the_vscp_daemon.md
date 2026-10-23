# Configuring the VSCP tcp/ip Daemon

The configuration file is used to tell which drivers should be used and how the VSCP tcp/ip daemon should operate. From version 15.0 this file has changed format from XML to JSON.

As always with configuration files it easy to make changes that make the system nonfunctional. So be careful when you edit the file and keep to the JSON standard. Most important keep a backup so that you can go back to a working copy if something goes wrong.

It is very convenient to use one of the online JSON validators to validate the JSON file when doing a lot of changes. There are many available and a good one is [this one](https://jsonformatter.curiousconcept.com/). Just copy the content of the file in the box and validate.

When you change something in the configuration file you have to restart the VSCP tcp/ip daemon for the changes to take effect. You do this with

```bash
sudo systemctl restart vscpd
```

If something is wrong the VSCP tcp/ip daemon may not start. Check the log file at **/var/log/vscpd.log**. You can also use

```bash
ps aux | grep vscpd
```

to see if the VSCP tcp/ip daemon is running or not.

When something goes wrong at this point is good to run the VSCP tcp/ip daemon stand alone like

```
sudo vscp -s -c /etc/vscp/vscpd.json
```

status data will go to the display and it is easy to see any errors.


The sample configuration file that is installed holds a lot of information. You can use defaults for most of it. A minimum configuration file looks like this

'''json
{
  "runasuser": "vscp",
  "guid": "FF:FF:FF:FF:FF:FF:FF:F5:00:00:00:00:00:00:00:00",
  "servername": "The VSCP tcp/ip daemon on hostx",
  "classtypedb": "/var/lib/vscp/vscpd/vscp_events.sqlite3",
  "maindb": "/var/lib/vscp/vscpd/vscp.sqlite3",
  "discoverydb": "/var/lib/vscp/vscpd/vscp.sqlite3",
  "vscpkey": "/etc/vscp/vscp.key",
  "logging": {
    "file-enable-log": true,
    "file-log-level": "debug",
    "file-pattern": "[vscp: %c] [%^%l%$] %v",
    "file-path": "/var/log/vscp/vscpd:.log",
    "file-max-size": 5242880,
    "file-max-files": 7,
    "console-enable-log": true,
    "console-log-level": "debug",
    "console-pattern": "[vscp: %c] [%^%l%$] %v",
    "syslog-enable-log" : false,
    "syslog-log-level" : "info",
    "syslog-ident" : "mqttvscpd",
    "udp-enable-log": false,
    "udp-log-level" : "info",
    "udp-pattern" : "[mqttvscpd] [%^%l%$] %v",
    "udp-host" : "127.0.0.1",
    "udp-port" : 9999
  }
'''

## Location of the configuration file

The daemon needs a configuration file called **vscpd:.json**. The server will not start without this file nor if the file contains invalid information or information on invalid format. Normally the installation program will create a default file.

On most machines the configuration file will be located in 

    /etc/vscp/vscpd:.json
    
The location that is searched to find the configuration file can be changed with switches when you start the daemon. see the section about [startup switches](http://www.vscp.org/docs/vscpd:/doku.php?id=vscp_daemon_startup_switches) for each platform.

## To think about before you start :id=think-before

### GUID's :id=think-before-guid

GUID's stands for **G**lobally **U**nique **ID**entifiers and this id is used in VSCP to identify thing. All devices and nodes are identified by a GUID but so is also the VSCP tcp/ip daemon (it is after all a node to) and each of the drivers connected to the server. Check the [VSCP specification](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_globally_unique_identifiers) for more information about GUID's. 

The GUID entered here should have the **four least significant bytes set to zero**. Byte 12/13 is used for interface id's (OBID in events) and byte 14/15 is used for nodes connected on a interface that does nicknames instead of full GUID's. The zeroed GUID is the GUID the daemon itself is identified by.

The daemon needs a GUID assigned to it. Preferably a unique one. It is possible to base a GUID on the machines IP address if it have an ethernet interface. The form will then be

    FF:FF:FF:FF:FF:FF:FF:FD:YY:YY:YY:YY:XX:XX:XX:XX

where the YY's will be the IPv4 address and the XX's set to zero as explained above.

There is also other id's to build upon. One can also ask for a personal assigned series. See [the VSCP specification](https://docs.vscp.org/#vscpspec) for more info on how.

For most users the IPv4 address of the machine the VSCP tcp/ip daemon is installed on is the best solution. 

##  Description of the configuration :id=config-description

The configuration file is a standard JSON file that contains information that tells the VSCP tcp/ip daemon what to do and how it should be done. The information in it is divided into sections and this documentation and each section and it's content is described below.

You can view a sample configuration file [here](https://github.com/grodansparadis/vscp/blob/master/resources/linux/vscpd:.json).

## The general section :id=config-general

In the general section you find settings that are common to all components of the VSCP tcp/ip daemon software. 

```json
"runasuser" : "vscp",		
"guid" : "-",
"key" : "Path to a file with a 128/192/256-bit encryption key on hex format"
"hmac" : "Path to a file with a 256 bit HMAC-SHA256 key on hex format"
"servername" : "The VSCP tcp/ip daemon on host",
"classtypedb" : "/var/lib/vscp/vscpd:/vscp_events.sqlite3",
"maindb" : "/var/lib/vscp/vscpd:/vscp.sqlite3",
"discoverydb" : "/var/lib/vscp/vscpd:/vscp.sqlite3",
"vscpkey" : "/var/vscp/vscp.key",

"logging" : {
    "file-enable-log": true,
    "file-log-level" : "debug",
    "file-pattern" : "[mqttvscp %c] [%^%l%$] %v",
    "file-path" : "/var/log/vscp/vscpd:.log",
    "file-max-size" : 5242880,
    "file-max-files" : 7,
    "console-enable-log": false,
    "console-log-level" : "info",
    "console-pattern" : "[mqttvscp %c] [%^%l%$] %v",
    "syslog-enable-log" : true,
    "syslog-log-level" : "info",
    "syslog-ident" : "vscpd:",
    "udp-enable-log": true,
    "udp-log-level" : "info",
    "udp-pattern" : "[mqttvscp] [%^%l%$] %v",
    "udp-host" : "127.0.0.1",
    "udp-port" : 9999
}
```

this will start up the daemon but do noting. You need to add a driver to get some work done.

### runasuser :id=config-general-runasuser

__Only on Unix/Linux__. User to run the VSCP tcp/ip daemon as. This is for security and folders for VSCP & friends are set up with permissions for a vscp user on install. By running on this user it is no need to run the VSCP tcp/ip daemon as the root user.

Change to the user you want or set to empty to run as the user who starts the VSCP tcp/ip daemon.


### guid :id=config-general-guid

```xml
<guid>
    FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:F5:00:00:00:00
</guid>
```

Set the server GUID for the daemon. This GUID is the base for the system. 

If not set here (or all nills) a GUID will be formed from the (first) MAC address of the machine the daemon runs on (on Linux needs to be run as root to get this) or if this fails the local IP address is used to form the GUID. The GUID string should be in MSB -> LSB order and have the four lsb set to zero.

**Example**
```
    FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:00:00:00:00
```

### Servername :id=config-general-servername

If set this real text name will be used as an identifier for the server along with the GUID. The default name will be something like

    The VSCP tcp/ip daemon

but you should set this to an id that make it easy to identify your server as it will be published to the MQTT server you setup at the topic mqttvscp-daemon/{{guid}} where {{guid}} is [the guid you used for the daemon](#config-general-guid).

### classtypedb :id=config-general-classtypedb
This is a path to a sqlite3 database file that holds information about VSCP events and can give symbolic output from the VSCP tcp/ip daemon. You can for instance have topics that display class or type as token instead of the numerical code. Live this entry blank if you have no interest in this.

Events are added to the VSCP specification as times go by. The database installed with the VSCP tcp/ip daemon is the current at the moment of the release. If you want to update you can find the latest version [here](https://www.vscp.org/events/vscp_events.sqlite3). Update information is [here](https://www.vscp.org/events/version.json). 

Load the latest file with

```bash
cd /var/lib/vscp
sudo wget https://www.vscp.org/events/vscp_events.sqlite3
```

### vscpkey :id=config-general-key

This is the path to a 128/192/256-bit encryption key used for AES 128/192/256 encryption. Used for the VSCP binary protocol. This file should only be readable by the user the vscp tcp/ip daemon is running under. You can generate a random key on [this site](https://randomkeygen.com/aes-key)

### hmak :id=config-general-hmac

This is the path to a 256-bit encryption key used for HMAC-SHA-256. Used for the VSCP binary protocol. This file should only be readable by the user the vscp tcp/ip daemon is running under. You can generate a random key on [this site](https://randomkeygen.com/hmac-key).


### maindb :id=config-general-maindb
THis is the main database file for the VSCP tcp/ip daemon. It's main content is the discovery database which is used to collect information about nodes in the system. 

This entry must point to a named file in a location that is writable (default is _/var/lib/vscp/vscpd:/vscp.sqlite3_)

### vscpkey :id=config-general-vscpkey
This is the path to a security key that the VSCP tcp/ip daemon use to encrypt/decrypt information with. The default is _/var/vscp/vscp.key_ This file should only be editable by the root user and also not be possible to read by any one else.

### debuglevel :id=config-general-debug-level
This is the debug level. Zero is no debugging. A higher number is different levels of debugging detail.

### logging :id=config-general-logging
This is the log console and file settings. Default is to log to the logfile */var/log/vscp/vscpd:.log* on Linux and *\program files (x86)\vscp\vscp.log* on Windows. The exception is at vscpd: start up, before the configuration file is read and the configured location for the log file is unknown, here logging is done to the console and on Linux also to the syslog.

Modes for logging can be set as of below. In debug/trace mode the debug flag above defines how much info is logged.

#### Logging to file

##### file-enable-log :id=config-general-logging-file-enable-log
Enable logging to a file by setting to *true*.

##### file-log-level :id=config-general-logging-file-log-level
Log level for file log. Default is "info".

| Level | Description |
| ----- | ----------- |
| "trace" | Everything is logged |
| "debug" | Everything except trace is logged |
| "info" | info and above is logged |
| "err" | Errors and above is logged |
| "critical" | Only critical messages are logged |
| "off" | No logging |

##### file-pattern :id=config-general-logging-file-pattern
Log file pattern as described [here](https://github.com/gabime/spdlog/wiki/3.-Custom-formatting).

##### file-path :id=config-general-logging-file-path

Path to log file. Default is on Linux is */var/log/vscp/vscpd:.log*

##### file-max-size :id=config-general-logging-file-max-size
Max size for log file. It will be rotated if over this size. Default is 10 Mb.

##### file-max-files :id=config-general-logging-file-max-files
Maximum number of log files to keep. Default is 3.

#### Logging to console

##### console-enable-log :id=config-general-logging-console-enable-log
Enable logging to a console by setting to *true*.

##### console-log-level :id=config-general-logging-console-log-level
Log level for console log. Default is "info".

| Level | Description |
| ----- | ----------- |
| "trace" | Everything is logged |
| "debug" | Everything except trace is logged |
| "info" | info and above is logged |
| "err" | Errors and above is logged |
| "critical" | Only critical messages are logged |
| "off" | No logging |

##### console-pattern :id=config-general-logging-console-pattern

Format for consol log. Default is __"[vscp] [%^%l%$] %v"__


#### Logging to syslog (Unix and macintosh)

Logging to the standard logging mechanism on Unix like systems.  

##### syslog-enable-log :id=config-general-logging-syslog-enable-log
Enable logging to a console by setting to *true*.

##### syslog-log-level :id=config-general-logging-syslog-log-level
Log level for console log. Default is "info".

| Level | Description |
| ----- | ----------- |
| "trace" | Everything is logged |
| "debug" | Everything except trace is logged |
| "info" | info and above is logged |
| "err" | Errors and above is logged |
| "critical" | Only critical messages are logged |
| "off" | No logging |

##### syslog-ident :id=config-general-logging-syslog-ident
This set to "vscpd:" as default and is the program identifier tag that gets attached to every log line syslog receives from your application — it's how syslog (and anything reading its output) knows which program sent a given message.

#### Logging to UDP

UDP log messages are sent to a specific UDP host address and port.

##### console-enable-log :id=config-general-logging-console-enable-log
Enable logging to a UDP by setting to *true*.

##### console-log-level :id=config-general-logging-console-log-level
Log level for UDP log. Default is "info". Note that __"info"___ is probably the maximum level yoy normally want to set not to overload your network.

| Level | Description |
| ----- | ----------- |
| "trace" | Everything is logged |
| "debug" | Everything except trace is logged |
| "info" | info and above is logged |
| "err" | Errors and above is logged |
| "critical" | Only critical messages are logged |
| "off" | No logging |

##### udp-pattern :id=config-general-logging-udp-pattern

Format for udp log messages. Default is __"[mqttvscp] [%^%l%$] %v"__

##### udp-host :id=config-general-logging-udp-host

UDP host to send log messages to. Should be IP-address Default is "127.0.0.1"

##### udp-port :id=config-general-logging-udp-port

UDP port to send log messages to. Default is 9999


## TCP/IP server :id=config-tcpip

The `tcpip` object configures the daemon's TCP/IP listeners.

### interface-address :id=config-tcpip-interface-address

Specify one listening address as a string, or multiple listening addresses as an array of strings. Each address is a URL containing a scheme, host or IP address, and port.

One listening address:

```json
{
  "tcpip": {
    "interface-address": "tcp://localhost:9598"
  }
}
```

Multiple listening addresses:

```json
{
  "tcpip": {
    "interface-address": [
      "tcp://127.0.0.1:9598",
      "tcp://127.0.0.1:9599"
    ]
  }
}
```

Each array element defines a separate listener. Use distinct address/port combinations that can be bound simultaneously; do not put multiple addresses in a comma-separated string.

Use `tcp://` for plain TCP or `tls://` for TLS. Different listeners may use different schemes. All TLS listeners share the certificate and key configured under `tcpip.ssl-options`. See [Security and TLS](./security_tls.md) for TLS configuration.

Loopback addresses such as `127.0.0.1` accept local connections only. An address such as `0.0.0.0` listens on all IPv4 interfaces; use TLS for listeners reachable from other machines.

##  Level I Drivers :id=config-level1-driver

Define a VSCP tcp/ip daemon level I driver. If enabled the driver will be loaded. 

Level I drivers was in the past called CANAL (CAN Abstraction Layer) drivers (just because they are).


```json
"level1" : [
{
    "enable" : false,
    "name" : "logger",
    "config" : "/tmp/canallog.txt",
    "flags" : 1,
    "translation" : 2,
    "path" : "/var/lib/vscp/drivers/level1/vscpl1drv-logger.so",
    "guid" : "FF:FF:FF:FF:FF:FF:FF:F5:01:00:00:00:00:00:00:01"
}
```

The content consist of one or several driver entries in an array each representing a level 1 driver that should be used. 

### enable :id=config-level1-driver-enable

Set to true to enable loading of the driver, set to false to disable.

### name :id=config-level1-driver-name

A name given by the user for the driver. This is the name by which the driver is identified bym by the system.

### config :id=config-level1-driver-config

The semicolon separated configuration string for the driver. The meaning of this string is driver specific. See documentation for the driver.

### flags :id=config-level1-driver-flags

Can be set as a devimal number or a hexadecimal, octal or binary string prefixed with "0x", "0o", "ob".

This is a 32 bit driver specific number that have bits set that have special meaning for a driver. See the documentation for a specific driver for an explanation of the meaning of each flag bit for that driver. Given as a number 

### path :id=config-level1-driver-path

This is the path to where the driver is located. Usually points to a file located in in the folder _/var/lib/vscp/drivers/level1/_ where level I drivers by default will be installed.

### guid :id=config-level1-driver-guid

__Must be set to a unique and valid GUID.__   

The GUID that the driver will use for it's interface. This means that this is the GUID that will be the source of Level I events.

Note that the GUID set here should have the two least significant bytes set to zero as they are reserved for nickname id's.

### Translation :id=config-level1-driver-translation

This is a list of semicolon separated fields with translations that should be carried out by the system on event passing through driver.

 | Mnemonic  | Description  | 
 | :--------:  | -----------  | 
 | Bit 1 (1) | Incoming Level I measurement events is translated to Level II measurement, floating point events. | 
 | Bit 2 (2) | Incoming Level I measurement events is translated to Level II measurement, string events.  | 
 | Bit 3 (4) | All incoming events will be translated to class Level I events over Level II, that is have 512 added to it's class. | 

----

## Level II drivers :id=config-level2-driver

Level II drivers can handle the full VSCP abstraction and don't have the small level I maximum payload size of eight bytes and other limitations of the Level I drivers.

[HLO (High Level Objects)](https://grodansparadis.github.io/vscp-doc-spec/#/./class2.hlo) are also understod by this type of drivers.

```json
{
    "enable" : false,
    "name" : "Logger",
    "path-driver" : "/var/lib/vscp/drivers/level2/vscpl2drv-logger.so",
    "path-config" : "/var/lib/vscp/vscpd:/logger2.conf",
    "guid" : "FF:FF:FF:FF:FF:FF:FF:F5:02:00:00:00:00:00:00:01",
},
```

### enable :id=config-level2-driver-enable

The driver should be loaded if set to true. If false the driver will not be loaded.

### name :id=config-level2-driver-name

A name given by the user for the driver. Should not contain spaces.

### path-driver :id=config-level2-driver-path-driver

This is the path to the driver. Usually points to a file located in _/var/lib/vscp/drivers/level2/_ which is the default installation folder for level II drivers.

### path-config :id=config-level2-driver-path-config

This is the path to the driver configuration file. This file can be located in /etc/vscp for best security or in _/var/lib/vscp/_ if the HLO write ability should be used or in any other suitable place on your disk.

The format of this file is up to the driver creator. JSON format is most common but XML and other formats are also valid.

###  guid :id=config-level2-driver-guid

__Must be set to a unique and valid GUID.**

The GUID that the driver will use for it's interface.


[filename](./bottom_copyright.md ':include')
