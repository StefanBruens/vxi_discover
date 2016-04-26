# vxi_discover
Small tool to discover VXI-11 cabable measurement devices using broadcasts

To discover the devices on your network just run:

$> make

$> ./vxi_discover -b

You can also query for the VXI-11 RPC service using unicast:

$> ./vxi_discover 192.168.1.20

## How it works

vxi_discover assembles a RPC request to the PortMapper, asking it for the
TCP port of the VXI-11 core service. It then sends the request on all interfaces
via UDP:
* to the IPv4 broadcast address
* to the IPv6 multicast address for RPC calls (ff02::202)
