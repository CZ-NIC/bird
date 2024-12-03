# Project roadmap

## Planned for 2025

*Not decided yet.*

## Expected features

*The order of these items is not significant.*

### EVPN / VXLAN extensions
There is an out-of-tree branch which we intend to continue work on and
eventually merge.

### Enhanced command-line interface
Most other vendors allow for updating the configuration from the command-line.
There is quite some demand to allow this with BIRD. Needs quite some refactoring
before possible.

### SNMP AgentX plugin for BIRD status export
Allow for easier status monitoring.

### BGP Optimal Route Reflection (RFC 9107)
Implement BGP best route selection on route reflectors to adhere to POV of
client, not RR. Also requested by somebody, don't remember who and when.

### OSPF Traffic engineering extensions (RFC 3630)
Requested in list. May include lots of other RFC's as we have neglected this
feature for a long time.
http://trubka.network.cz/pipermail/bird-users/2022-January/015911.html

### BGP minimum route advertisement interval (MRAI)
BGP specifies minimum interval between route advertisements for the same
network. This is not implemented in BIRD. It should be implemented for 3.0 to
avoid unnecessary re-routing spikes.

### OSPF unnumbered interfaces
The OSPFv2 protocol allows interfaces that do not have proper IP range but have
peer IP addresses (like PtP links). It should be extended to also allow true
unnumbered interfaces with no addresses (by using an IP address from some
loopback device). This would require to have stricter separation between IP
addresses and interfaces in OSPFv2.

### OSPF Segment Routing Extension (RFC 8665)
MPLS label distribution using segment routing and simple OSPF extension.

### MPLS Label Distribution Protocol (LDP)
Label Distribution Protocol (RFC 5036) is a protocol for establishing
label-switched paths and distributing of MPLS labels between MPLS routers.
These paths and labels are based on existing unlabeled routing information.

### SRv6 support (RFC 8986)
Segment Routing over IPv6, SID assignments, Linux kernel support.

### Seamless BFD
New version of BFD negotiation defined in RFC 7880-7886 enables faster
continuity tests by dissemination discriminators by the governing protocols.

### OSPF Graceful Link Shutdown
To enable seamless maintenance of single links, OSPF can advertise such a link
getting down in advance, allowing to re-route. Defined in RFC 8379.

### IS-IS
IS-IS routing protocol is a nice-to-have alternative to OSPF.

### BGPsec
BGPsec (RFC 8205) is a new path security extension to BGP.

### BGP Link State extension
BGP-LS allows to transport information about network topology across BGP links.
This should help e.g. to run traffic-engineering between more confederated ASs.
Also needed to implement Seamless BFD on BGP: RFC 9247

### VPP / DPDK direct programming support
Module allowing to directly export routes to VPP, instead of playing ping-pong
with Netlink. Also possibly tighter integration, depends of user needs.

### Flowspec to kernel / VPP interface
BGP Flowspec are actually firewall rules, so either nftables or direct hardware
programming is what we need to execute them.

### Flowspec attribute filtering
Flowspec routes have many parameters, but these are not accessible from filters.
Filters should be extended to access all these attributes, but first it is
necessary to cleanup attribute handling in filters.

## Refactoring and internal plans

### Nexthop attributes and ECMP filtering
Currently we have route attributes, but with ECMP routes it is necessary to
store per-nexthop data (like weight or encapsulation). We also do not have
proper way to manipulate with multiple nexthops from filters. Attributes should
be extended to allow per-nexthop ones and filters should be extended to allow
access multiple nexthops and their attributes.

### OSPFv3 Extended LSAs
Implement RFC 8362. Needed for most of the newer OSPF features.

### Automatic performance testing
Integrated perftests into CI.

### IPv6 preference in documentation (?)
Address world's reluctance of legacy IPv4 deprecation by updating the
documentation in such a way that IPv6 is preferred and first seen.

### Improved VRF support
BIRD has working VRF support, but it needs improvements. VRF entities should be
first-class objects with explicit configuration, with a set of properties and
default values (like default routing tables, or router ID) for associated
protocols. Default kernel table ID should be autodetected. There should be
better handling of VRF route leaking - when a route is propagated between VRFs,
its nexthop should reflects that. Setup of VRFs in OS is out of scope.

### Linux kernel nexthop abstraction
Netlink allows setting nexthops as objects and using them in routes. It should
be much faster than conventional route update.

### Protocol attributes for filtering
Filters can access route attributes, but sometimes it could be useful to access
attributes of associated protocol (like neighbor-as or neighbor-ip for BGP
protocol). But it would require to have internal object model (below) first,
as we do not want to implement it independently for each protocol attribute.

### Interface and address table rework
The current state of two linked lists is becoming too limiting for certain use
cases. We are looking into conversion of these tables into some faster and
better accessible structures.

### Internal object model
We need to define explicit internal object model, where existing objects
(protocols, channels, tables, routes, interfaces ...) and their properties are
described in a way that allows introspection sufficient for implementing
features (control protocol, CLI, filter access, perhaps reconfiguration) in a
generic manner.

### Generic configuration model
Configuration options are implicitly defined by the configuration parsing code.
We need to define explicit configuration model independent of the parsing code
and generic parsing code using that model. This will allow uniform validation of
configuration properties, generic access to configuration from control protocol
and possibly independent configuration backends (like one for Netconf).

### New control protocol
BIRD should have a well-documented machine readable protocol. Requirements for
such protocol are:

* Generic machine readable abstract-tree representation (like CBOR)
* Both request/reply and subscribe/notify access patterns
* Access objects and properties using internal object model
* In-band introspection based on internal object model

From Maria's notes:

* CBOR-based protocol for both control and route exports
* Python3 library with example implementation of CLI
* (maybe) Ansible modules
* RFC 9164: CBOR tags for IP addresses and prefices
* RFC 9254: YANG-CBOR mapping
* RFC 9277: Stable storage of CBOR (files)

Maybe, after generic configuration model is created, this may be a CORECONF
implementation.

### Netconf
Network Configuration Protocol (RFC 6241) is a XML/JSON protocol for
configuration management of network devices. This would be an overlay daemon
translating between XML (Netconf) or JSON (Restconf) and CBOR (Coreconf).

## Long-term thoughts

*We don't know whether we want this to be implemented in BIRD.*

### DHCP implementation
Ranging from DHCPv6 relay agents (RFC 8415, RFC 8987) to ensure that prefixes
delegated by DHCPv6-PD are routable, to actual full DHCPv6 (and DHCPv4) server
and maybe even a client.

### Configuring interfaces
There is a long rabbit-hole of what we allow ourselves to implement considering
the network interfaces. We have identified 4 different possible scenarios and
not decided on any of these yet.

0. we do nothing
1. we implement only what we really need (e.g. creating pseudo-interfaces for VXLAN)
2. we implement common things including interface address setting or changing its state
3. we go full NetworkManager

### LLDP implementation
Autodiscovery allowing also for autoconfiguration of other protocols.

### Wireguard routing support
The internal Wireguard routing is weird and we may want to explicitly route by
e.g. Babel in a complex network of tunnels. Or, if we decide to implement
interface configuration, we may even create interfaces based on whatever the
user configures.

### IPv4 multicast
Basic infrastructure for IPv4 multicast routing, including nettypes for
multicast routes and multicast requests, multicast kernel protocol and IGMPv2
protocol.

### PIM-BIDIR
Bidirectional PIM (RFC 5015) is a multicast routing protocol, variant of PIM-SM.
It uses bidirectional shared trees rooted in Rendezvous Point (RP) to connect
sources and receivers.

There is an old branch containing this. We should have merged this years ago.

### IPv6 multicast
Basic infrastructure for IPv6 multicast routing, including nettypes for
multicast routes and multicast requests, multicast kernel protocol and MLDv1
protocol. Most of these (with the exception of MLDv1) is just a variant of
IPv4 multicast.

### IGMP/MLD multicast proxy
A simple IGMP/MLD multicast proxy, which sends IGMP/MLD requests on a configured
uplink interface based on received requests on downlink interfaces, and updates
associated multicast routes.

### Source-specific multicast (SSM)
Infrastructure for multicasts should be extended to handle source-specific
multicasts. Extend multicast nettypes to include source addresses, handle them
in multicast kernel protocols and implement IGMPv3/MLDv2 protocols.

### PIM-SSM
PIM-SSM is a source-specific multicast routing protocol, a subset of PIM-SM
protocol (RFC 7761). It is restricted to source-specific multicasts, which
eliminates many problematic parts of PIM-SM.

### PIM-SM
PIM-SM (RFC 7761) is a prevailing multicast routing protocol, but more
complicated than PIM-BIDIR and PIM-SSM.

### BFD Multipoint Connectivity
Checking whether multiple "receivers" can communicate with a single "sender".
Possibly useful after merging PIM-BIDIR and implementing other PIMs. RFC 8562-8563.

### Mutable static routes
Extension to the static protocol that would allow to add/remove/change static
routes from CLI.

### Multipipe
Pipe-like protocol: When a route is exported to this protocol, it runs its
filter extended with capability to announce any number of new routes to any
table from one filter run. Its primary purpose is to allow user-specified
route aggregation and other non-linear operations.

## Minor

* RFC 8510: OSPF LLS Extension for Local Interface ID Advertisement
* RFC 8538: BGP Graceful Restart Hard Reset
* RFC 8326: BGP Graceful Session Shutdown Community auto-apply
* RFC 8962: Become part of the IETF Protocol Police
* RFC 9072: Extended Optional Parameters Length for BGP OPEN Message
* RFC 9339: OSPF Reverse Metric
