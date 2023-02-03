# Project roadmap

## Planned for 2023

### SNMP AgentX plugin for BIRD status export
Allow for easier status monitoring.

### BGP Monitoring Protocol (BMP)
BGP Monitoring Protocol (RFC 7854) is a protocol between a BGP speaker and
a monitoring node, which is notified about route updates and neighbor state
changes of the BGP speaker.

### Better coverage of automatic tests
Functionality tests should cover more possible configurations and
combinations. Integration tests should run automatically between different OS
versions and HW architectures. Experimental support for performance regression tests.

### Release 3.0-alpha1
Missing: MRT, merging

### Show BFD sessions details
CLI command showing detailed information about BFD sessions state

### Review and merge Babel extended next hop patches (RFC 9229)
Babel extension to allow IPv4 routes with IPv6 next hop. Patch on mailing list.

### Consolidate protocol statistics
Consolidate protocol statistics, make them useful for SNMP plugin and implement
'show XX stats' command.

### TCP-AO if it appears in Linux and BSD upstream
Resolve whether we should or shouldn't control the kernel key management.
Design and implement our side for both Linux and BSD.

### Conditional routes (v3)
Filters should be extended to allow conditional expressions based on a number of
matching routes in a routing table. This would allow to specify aggregate routes
using a static protocol and conditions like 'if there is at least 1000 routes
from this BGP protocol, accept this default route'. This feature comes handy
when a router needs to detect whether its BGP upstream is alive and working.
Based of number of routes received, the router can then announce or retract a
default route to OSPF, making multi-exit network routing simpler and more
effective.

### Aggregating routes
Requested by customer: aggregating multiple routes by a common set of attributes.

Implementation choice: the user specifies

    EXPORT filter before aggregation AGGREGATE ON list of expressions to compare MERGE what to do with the remaining attributes

Example usage:

* aggregating information from multiple internal BGP routes into one external
* creating a multipath route from multiple BGP routes (currently done by MERGE PATHS)
* (in future) computing a minimal route set for kernel to make forwarding faster instead of writing the received full BGP set there

### PREF64 option in RA (RFC 8781)
Inform hosts about prefix used to synthesize NAT64 addresses. Requested in list:
http://trubka.network.cz/pipermail/bird-users/2022-November/016401.html

### Logging via UDP
Got a patch, probably never merged. May be useful.
http://trubka.network.cz/pipermail/bird-users/2022-January/015893.html

### BGP Tunnel Encapsulation Attribute (RFC 9012)
Packets sent to BGP next hop may be encapsulated using various tunnel
technologies. Useful for L3VPN.

### BGP AS Cones and ASPA support
Extend the RPKI protocol with AS Cones and ASPA loading. Implement AS Cones
and ASPA validation routines. There may be some pending patches from QRator.

### DHCPv6 relay agent
DHCPv6 relay agents (RFC 8415, RFC 8987) forward DHCPv6 messages between clients and
servers. They also ensure that prefixes delegated by DHCPv6-PD are routable,
i.e. they should generate routes for these prefixes.

### Nexthop attributes and ECMP filtering
Currently we have route attributes, but with ECMP routes it is necessary to
store per-nexthop data (like weight or encapsulation). We also do not have
proper way to manipulate with multiple nexthops from filters. Attributes should
be extended to allow per-nexthop ones and filters should be extended to allow
access multiple nexthops and their attributes.

### Performance accounting
Extended internal statistics about time spent in different modules of BIRD. If
the route server admin checks why it takes 15 minutes to converge, this should
give some basic info about performance. [MM: Internally needed by 3.0, already in progress]

### MPLS support
Finalize and merge improved MPLS infrastructure (including MPLS label allocator
and supporting code), improve its reconfiguration support and support for
segment routing.

### BGP Segment Routing Extension (RFC 8669)
Receive and announce Segment Identifiers (SIDs) for BGP next hops.

## Backlog for following years

*The order of these items is not significant.*

### Flowspec attribute filtering
Flowspec routes have many parameters, but these are not accessible from filters.
Filters should be extended to access all these attributes, but first it is
necessary to cleanup attribute handling in filters.

### BGP Optimal Route Reflection (RFC 9107)
Implement BGP best route selection on route reflectors to adhere to POV of
client, not RR. Also requested by somebody, don't remember who and when.

### OSPF Traffic engineering extensions (RFC 3630)
Requested in list. May include lots of other RFC's as we have neglected this
feature for a long time.
http://trubka.network.cz/pipermail/bird-users/2022-January/015911.html

### IPv6 preference in documentation (?)
Address world's reluctance of legacy IPv4 deprecation by updating the
documentation in such a way that IPv6 is preferred and first seen.

### BGP local prefix leak prevention (?)
Reject local prefixes on eBGP sessions by default to prevent leaks to public Internet.
Unless explicitly enabled by config, of course.

### Re-bogonization of 240/4 legacy range (?)
We shouldn't believe that every operator does the
filtering right and they could simply rely on pre-2.0.10 behavior which
filtered this out by default.

### IPv4 multicast
Basic infrastructure for IPv4 multicast routing, including nettypes for
multicast routes and multicast requests, multicast kernel protocol and IGMPv2
protocol.

### PIM-BIDIR
Bidirectional PIM (RFC 5015) is a multicast routing protocol, variant of PIM-SM.
It uses bidirectional shared trees rooted in Rendezvous Point (RP) to connect
sources and receivers.

There is an old branch containing this. We should have merged this years ago.

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

### Mutable static routes
Extension to the static protocol that would allow to add/remove/change static
routes from CLI.

### Multipipe
Pipe-like protocol: When a route is exported to this protocol, it runs its
filter extended with capability to announce any number of new routes to any
table from one filter run. Its primary purpose is to allow user-specified
route aggregation and other non-linear operations.

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

### Seamless BFD
New version of BFD negotiation defined in RFC 7880-7886 enables faster
continuity tests by dissemination discriminators by the governing protocols.

### OSPF Graceful Link Shutdown
To enable seamless maintenance of single links, OSPF can advertise such a link
getting down in advance, allowing to re-route. Defined in RFC 8379.

## Long-term

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

## Perhaps

### IS-IS
IS-IS routing protocol is a nice-to-have alternative to OSPF.

### BGPsec
BGPsec (RFC 8205) is a new path security extension to BGP.

### PIM-SM
PIM-SM (RFC 7761) is a prevailing multicast routing protocol, but more
complicated than planned PIM-BIDIR and PIM-SSM.

### Netconf
Network Configuration Protocol (RFC 6241) is a XML/JSON protocol for
configuration management of network devices. It would benefit from generic
configuration model (above).

### NetConf overlay
Machine-friendly config file editor daemon (standalone) with standard NetConf
interface on one side and BIRD config file + reconfiguration requests on the
other side. Python3 seems to be better choice than C for this kind of work.

### Backend for 802.11r
Let's assume a bunch of boxes, all having some public wifi APs and some (secure) uplinks.
Design and implement an automatic backbone protocol to allow for simple almost-zeroconf
setup of e.g. a conference room or train / bus public wifi or even a local home network,
all with hostapd seamlessly transferring clients between APs via 802.11r.
Possible collab with Turris.

### BFD Multipoint Connectivity
Checking whether multiple "receivers" can communicate with a single "sender".
Possibly useful after merging PIM-BIDIR and implementing other PIMs. RFC 8562-8563.

### BGP Link State extension
BGP-LS allows to transport information about network topology across BGP links.
This should help e.g. to run traffic-engineering between more confederated ASs.
Also needed to implement Seamless BFD on BGP: RFC 9247

### Locator/ID Separation Protocol
LISP intends to break up addressing to Routing Locators and Endpoint
Identifiers. This may help multihoming networks in future. RFC 9299-9306.

### Backend for IPv6 Multihoming without BGP
Implement and configure BIRD in such a way that local nodes are seamlessly
connected to the Internet via multiple upstreams, using Network Prefix
Translation and other techniques. Possible collab with Turris.

## Minor

* RFC 8510: OSPF LLS Extension for Local Interface ID Advertisement
* RFC 8538: BGP Graceful Restart Hard Reset
* RFC 8326: BGP Graceful Session Shutdown Community auto-apply
* RFC 8962: Become part of the IETF Protocol Police
* RFC 9072: Extended Optional Parameters Length for BGP OPEN Message
* RFC 9339: OSPF Reverse Metric
