# netbug
Netbug is a network debugging tool intended to make it simple to where network packets are lost at the protocol level.

## Overview
### Behavior
A behavior represents a group of packets traveling over a network with the same protocol, sources, and destinations. For
example, tcp packets travelling from a workstation to a server via ssh. in a configuration file this could be
represented like this:

```toml
[[behavior]]
protocol = "tcp"
src = "127.0.0.1"
dst = "192.168.0.2:22"
command = ["ssh", "192.168.0.2"]
```
NOTE: as in the example above if you specify a `command` you must specify teh same target ip (`192.168.0.2` is
explicitly written in both the `command` and `dst` fields)

### Client
The client is the simple piece of Netbug. Its only role is to produce, record, and upload network traffic to a server as
pcap files. The client has default network traffic  for the supported protocols; however, in some cases it is beneficial 
to use custom commands. The example behavior in the previous sections leverages this to ensure that ssh is using tcp
rather than udp while also ensuring that ALL aspects of the 3-way handshake is completed as expected.

#### Configuration
Field | Description | Default
----- | ----------- | -------
script_dir | specifies a directly to look in for custom scripts to use when generating a behavior's network traffic (currently ignored DO NOT USE)
pcap_dir | the directory in which pcaps of the recorded network traffic are stored, each interface will have its own pcap in this directory (ex lo.pcap.) | `/etc/netbug.d/pcap`
interfaces | a list of the target interfaces, if empty no traffic will be recorded
srv_addr | the address of the sever to send the recorded pcaps
interval | the time between each round of behavior traffic generation in the form "[0-9]*[sSmMhH]" | 10m (10 minutes)
filter | a custom Berkley Packet Filter to apply when recording traffic, the client will make a best effort attempt to filter out any extraneous data. omit to use the client generated filter, or provide an empty string to allow ALL traffic through
behaviors | a list of the behaviors to generate traffic for the client to generate, while you can specify a src address it will be ignored.
allow_concurrent | allow the client to generate all network traffic in parallel or sequentially | False

### Server
The server is responsible for receiving recorded network traffic from clients while also producing reports on the
status of each configured behavior. This means that for each behavior specified by a client, it must also be specified
in the server configuration. The good news, is that you can simply copy+paste all simple behaviors from the client and
all non-relevant fields such as command will simply be ignored.

#### Configuration
Field | Description
----- | -----------
pcap_dir | the directory to store the pcaps received from clients separated first by host / ip adn teh by interface | `/etc/netbug.d/pcaps
srv_addr | the address to bind teh sever to | 127.0.0.1:8081
behaviors | the list of behaviors to use for pcap analysis
report_dir | the directory in which the generated reports will be stored | `etc/nbug.d/report`
overwrite_report | continuously overwrite the old report, ro create  a new report each time identified with a unique timestamp