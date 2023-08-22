%global _hardened_build 1
%global _without_doc 1
%{!?_rundir:%global _rundir %%{_localstatedir}/run}

Name:             bird
Version:          {{ version }}
Release:          cznic.{{ release }}%{?dist}
Summary:          BIRD Internet Routing Daemon

Group:            System Environment/Daemons
License:          GPL-2.0-or-later
URL:              https://bird.network.cz/
Source0:          https://bird.network.cz/download/bird-%{version}.tar.gz
Source1:          bird.service
Source2:          bird.tmpfilesd
Source3:          bird.sysusersd

BuildRequires:    autoconf
BuildRequires:    flex
BuildRequires:    bison
BuildRequires:    ncurses-devel
BuildRequires:    readline-devel
BuildRequires:    sed
BuildRequires:    gcc
BuildRequires:    make
BuildRequires:    libssh-devel
%if 0%{?rhel} && 0%{?rhel} < 8
# http://trubka.network.cz/pipermail/bird-users/2019-August/013631.html
BuildRequires:    devtoolset-8-toolchain
%endif
BuildRequires:    systemd-rpm-macros
%{?systemd_requires}
%{?sysusers_requires_compat}

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
Group:            Documentation
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
%setup -q -n bird-%{version}

%build
%if 0%{?rhel} && 0%{?rhel} < 8
. /opt/rh/devtoolset-8/enable
%endif

%configure --runstatedir=%{_rundir}/bird
%make_build all %{!?_without_doc:docs}

%install
%make_install

{% raw %}
install -d %{buildroot}{%{_localstatedir}/lib/bird,%{_rundir}/bird}
install -D -p -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/bird.service
install -D -p -m 0644 %{SOURCE2} %{buildroot}%{_tmpfilesdir}/bird.conf
install -D -p -m 0644 %{SOURCE3} %{buildroot}%{_sysusersdir}/bird.conf
{% endraw %}

%check
%if 0%{?rhel} && 0%{?rhel} < 8
. /opt/rh/devtoolset-8/enable
%endif

make test

%pre
%sysusers_create_compat %{SOURCE3}

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
%{_sysusersdir}/bird.conf
%{_tmpfilesdir}/bird.conf
%{_sbindir}/bird
%{_sbindir}/birdc
%{_sbindir}/birdcl
%dir %attr(0750,bird,bird) %{_localstatedir}/lib/bird
%dir %attr(0750,bird,bird) %{_rundir}/bird

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
