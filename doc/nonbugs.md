# List of non-bugs

We sometimes receive bug reports that describe unexpected behavior
but for some reason we don't consider them bugs. This includes things like:

- workarounds for network or other device bugs
- RFC-mandated behavior
- intentional RFC deviation
- specific design choices
- theoretical bugs with no real-world impact

To avoid such reports in the future, here is a list of known non-bugs that were reported:


## Filter engine

### No limit on recursion

There is no explicit check on the call stack exhaustion and implementing the
checks would have performance impact. The only method to crash BIRD by this is
by writing a recursive function into the configuration, which is by itself
a privileged operation.


## RIP

### RIP cryptographic authentication accepts replayed packets with the current sequence number

RFC 4822 section 2 specifies that cryptographic sequence numbers are
non-decreasing, therefore accepting packets with the same sequence number
as the previous one is mandatory for RFC-compliance and interoperability.

BIRD itself uses (modified) real time in seconds as sequence numbers.


## OSPF

### OSPFv2 cryptographic authentication accepts replayed packets with the same sequence number

RFC 2328 section D.3 specifies that cryptographic sequence numbers are
non-decreasing, therefore accepting packets with the same sequence number
as the previous one is mandatory for RFC-compliance and interoperability.

BIRD itself increases sequence number only when there is sufficient delay
between between sent packets to avoid issues with reordering.


### OSPFv3 accepts packets with non-link-local source address

While RFC 5340 section 2.5 specifies that OSPF packets are sent with link-local
source address, the section 4.2.2, which specifies checks for incoming packets,
does not contain such check for source address. Therefore, RFC-compliant
imlementations should accepts such packets.

## BGP

### BGP hold timer can be repeatedly started by invalid TCP data

When BGP hold timer triggers, it checks whether any new data has been received
before idling the connection.

This could be exploited by periodically sending garbage data to BGP, starting
hold timer repeatedly, thus keeping the BGP session open without sending any
keepalive messages.

However, an attacker would have to send data while BGP is busy and hold timer
triggers during this time. BGP would then start hold timer again to process
the data. Hold interval in BGP is randomized, which makes timing the attack
even harder. Moreover, an attacker would have to hijack an existing TCP
connection.

Successfully performing such an attack is highly unlikely.
