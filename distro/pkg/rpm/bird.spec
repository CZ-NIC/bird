%global _hardened_build 1
%global _without_doc 1

Name:             bird
Version:          {{ version }}
Release:          cznic.{{ release }}%{?dist}
Summary:          BIRD Internet Routing Daemon

License:          GPL-2.0-or-later
URL:              https://bird.network.cz/
Source0:          https://bird.network.cz/download/bird-%{version}.tar.gz
Source1:          bird.service
Source2:          bird.tmpfilesd

BuildRequires:    flex
BuildRequires:    bison
BuildRequires:    ncurses-devel
BuildRequires:    readline-devel
BuildRequires:    sed
BuildRequires:    gcc
BuildRequires:    make
BuildRequires:    libssh-devel
%if 0%{?fedora} || (0%{?rhel} && 0%{?rhel} > 7)
BuildRequires:    systemd-rpm-macros
%else
BuildRequires:    systemd
%endif

Obsoletes:        bird6 < 2.0.2-1
Provides:         bird6 = %{version}-%{release}

%description
BIRD is a dynamic IP routing daemon supporting both, IPv4 and IPv6, Border
Gateway Protocol (BGPv4), Routing Information Protocol (RIPv2, RIPng), Open
Shortest Path First protocol (OSPFv2, OSPFv3), Babel Routing Protocol (Babel),
Bidirectional Forwarding Detection (BFD), IPv6 router advertisements, static
routes, inter-table protocol, command-line interface allowing on-line control
and inspection of the status of the daemon, soft reconfiguration as well as a
powerful language for route filtering.

%if 0%{!?_without_doc:1}
%package doc
Summary:          Documentation for BIRD Internet Routing Daemon
BuildRequires:    linuxdoc-tools sgml-common perl(FindBin)
BuildArch:        noarch

%description doc
Documentation for users and programmers of the BIRD Internet Routing Daemon.

BIRD is a dynamic IP routing daemon supporting both, IPv4 and IPv6, Border
Gateway Protocol (BGPv4), Routing Information Protocol (RIPv2, RIPng), Open
Shortest Path First protocol (OSPFv2, OSPFv3), Babel Routing Protocol (Babel),
Bidirectional Forwarding Detection (BFD), IPv6 router advertisements, static
routes, inter-table protocol, command-line interface allowing on-line control
and inspection of the status of the daemon, soft reconfiguration as well as a
powerful language for route filtering.
%endif

%prep
%setup -q

%build
%configure --runstatedir=%{_rundir}/bird
%make_build all %{!?_without_doc:docs}

%install
%make_install

{% raw %}
install -d %{buildroot}{%{_localstatedir}/lib/bird,%{_rundir}/bird}
install -D -p -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/bird.service
install -D -p -m 0644 %{SOURCE2} %{buildroot}%{_tmpfilesdir}/bird.conf
{% endraw %}

%check
make test

%pre
getent group bird >/dev/null || groupadd -r bird
getent passwd bird >/dev/null || \
  useradd -r -g bird -d %{_localstatedir}/lib/bird -s /sbin/nologin \
  -c "BIRD daemon user" bird
exit 0

%post
%systemd_post bird.service

%preun
%systemd_preun bird.service

%postun
%systemd_postun_with_restart bird.service

%files
%doc NEWS README
%attr(0640,root,bird) %config(noreplace) %{_sysconfdir}/bird.conf
%{_unitdir}/bird.service
%{_tmpfilesdir}/bird.conf
%{_sbindir}/bird
%{_sbindir}/birdc
%{_sbindir}/birdcl
%dir %attr(0750,bird,bird) %{_localstatedir}/lib/bird
%dir %attr(0750,bird,bird) %ghost %{_rundir}/bird

%if 0%{!?_without_doc:1}
%files doc
%doc NEWS README
%doc doc/bird.conf.*
%doc obj/doc/bird*.html
%doc obj/doc/bird.pdf
%doc obj/doc/prog*.html
%doc obj/doc/prog.pdf
%endif

%changelog
* Wed Apr 07 2021 Jakub Ružička <jakub.ruzicka@nic.cz> - {{ version }}-cznic.1
- upstream package
