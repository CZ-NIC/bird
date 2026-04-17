## Security issues

Please contact us on bird-support@network.cz for private disclosure of any
security issues. This includes any crash in or related to filters, induced by
CLI or by receiving a malformed message by a protocol.

We take security issues seriously and we analyze them with high priority, often
even during weekends or nights, whenever something occurs. With that though,
we'd like you to first do your assessment whether the issue which you are about
to report, is indeed a security issue.

If you are using LLMs to find possible problems, we expect you to do the
following assessment before sending a report. In any case, write the report
yourself, proving that you actually understand what you are reporting.

### What is an issue for our security channel

**Do you get more power** compared to your regular
access level and available tools, **by exploiting that exact issue?** Yes?
Congratulations, you have found a security issue.

Parts of BIRD are expected to be exposed to the world. Thus, if you find a
misbehavior which may cause wrong routing/forwarding and is remote-triggerable
via BGP, RPKI or `birdc -r`, that is something worth sending through the
security channel.

BIRD runs with quite high privileges. If you need local `root` to exploit
the bug, it's **not a security issue**. If you need to build your binary yourself
with non-standard compiler flags, it's **not a security issue**.

BIRD has no quotas, query rate limiting or access control. If your root
left the control socket open, it's **not our security issue**. If you can saturate
the link so that BGP doesn't get through, it's **not our security issue**.

BIRD does not sanitize weird data from internal routing protocols.
If you are privileged enough to send garbage to OSPF, you are privileged
enough to spoof anything there. **Not a security problem** in BIRD.

BIRD expects operators to do reasonable things, and generally know what they
are doing. Crashes on configuration corner cases, weird combinations of debug
flags or crazy recursive filters are **not a security issue**, unless exploitable
unprivileged.

If unsure, use the security channel. If lazy, please do the assessment above :)