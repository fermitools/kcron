%define _hardened_build 1

%bcond_without libcap
%bcond_without systemtap
%bcond_without seccomp

%define client_keytab_dir /var/kerberos/krb5/user

Name:		fermilab-util_kcron

Version:	1.2
Release:	1%{?dist}
Summary:	A utility for getting Kerberos credentials in scheduled jobs

Group:		Fermilab
License:	MIT
URL:		https://github.com/scientificlinux/kcron
Source0:	kcron-%{version}.tar.gz

Provides:	kcron
Provides:	fermilab-util_kcron

%if %{_hardened_build}
BuildRequires: checksec
%endif

%if %{with libcap}
BuildRequires:  libcap libcap-devel
%endif
%if %{with systemtap}
BuildRequires:  systemtap-sdt-devel
%endif
%if %{with seccomp}
BuildRequires:  libseccomp-devel
%endif

BuildRequires:	cmake >= 3.14
BuildRequires:  asciidoc redhat-rpm-config coreutils bash gcc

Requires:       krb5-workstation >= 1.11
Requires:	util-linux


%description
The kcron utility has a long history at Fermilab.  It is useful
for running daemons and automatic jobs with kerberos rights.


%prep
%setup -q -n kcron
mkdir build


%build
cd build
%cmake3 -Wdev \
%if %{with libcap}
 -DUSE_CAPABILITIES=ON \
%else
 -DUSE_CAPABILITIES=OFF \
%endif
%if %{with systemtap}
 -DUSE_SYSTEMTAP=ON \
%else
 -DUSE_SYSTEMTAP=OFF \
%endif
%if %{with seccomp}
 -DUSE_SECCOMP=ON \
%else
 -DUSE_SECCOMP=OFF \
%endif
 -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
 -DCMAKE_RULE_MESSAGES:BOOL=ON \
 -Wdeprecated ..

make VERBOSE=2 %{?_smp_mflags}


%install
make install DESTDIR=%{buildroot}
%{__mkdir_p} %{buildroot}/%{kcron_keytab_dir}


%clean
rm -rf %{buildroot}

%check
for code in $(ls %{buildroot}%{_bindir}); do
    bash -n %{buildroot}%{_bindir}/${code}
    if [[ $? -ne 0 ]]; then
      exit 1
    fi
done
bash -n %{buildroot}%{_sysconfdir}/sysconfig/kcron
if [[ $? -ne 0 ]]; then
  exit 1
fi

%if %{_hardened_build}
for code in $(ls %{buildroot}%{_libexecdir}/kcron); do
    checksec -f %{buildroot}%{_libexecdir}/kcron/${code}
    if [[ $? -ne 0 ]]; then
      exit 1
    fi
    checksec -ff %{buildroot}%{_libexecdir}/kcron/${code}
    if [[ $? -ne 0 ]]; then
      exit 1
    fi
done
%endif

%files
%defattr(0644,root,root,0755)
%doc %{_mandir}/man1/*
%attr(0755,root,root) %{_bindir}/*
%config(noreplace) %{_sysconfdir}/sysconfig/kcron

%if %{with libcap}
%attr(0711,root,root) %caps(cap_chown=p cap_dac_override=p) %{_libexecdir}/kcron/init-kcron-keytab
%else
%attr(4711,root,root) %{_libexecdir}/kcron/init-kcron-keytab
%endif


%changelog

