%define _hardened_build 1

%bcond_without libcap
%bcond_without systemtap
%bcond_without seccomp

%if 0%{?rhel} < 9 && 0%{?fedora} < 31
%bcond_with landlock
%else
%bcond_without landlock
%endif

Name:		fermilab-util_kcron

Version:	1.8
Release:	1%{?dist}
Summary:	A utility for getting Kerberos credentials in scheduled jobs

Group:		Fermilab
License:	MIT
URL:		https://github.com/fermitools/kcron
Source0:	kcron.tar.gz

Provides:	kcron = %{version}-%{release}
Provides:	fermilab-util_kcron = %{version}-%{release}

%if %{_hardened_build}
BuildRequires: checksec openssl procps-ng
%endif

%if %{with libcap}
BuildRequires:	libcap libcap-devel
%endif
%if %{with systemtap}
BuildRequires:	systemtap-sdt-devel
%endif
%if %{with seccomp}
BuildRequires:	libseccomp-devel
%endif
%if %{with landlock}
BuildRequires:	kernel-devel
%endif

BuildRequires:	cmake >= 3.14
BuildRequires:	asciidoc redhat-rpm-config coreutils bash gcc

%if 0%{?rhel} < 10
BuildRequires:	gcc-toolset-13 scl-utils
%endif

Requires:	krb5-workstation >= 1.11
Requires:	util-linux coreutils


%description
The kcron utility has a long history at Fermilab.  It is useful
for running daemons and automatic jobs with kerberos rights.


%prep
%setup -q -n kcron


%build
%if 0%{?rhel} < 9 && 0%{?fedora} < 31
mkdir build
cd build
%endif

%if 0%{?rhel} < 10
source scl_source enable gcc-toolset-13
%endif

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
%if %{with landlock}
 -DUSE_LANDLOCK=ON \
%else
 -DUSE_LANDLOCK=OFF \
%endif
 -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
 -DCMAKE_RULE_MESSAGES:BOOL=ON \
 -DCLIENT_KEYTAB_DIR=%{_localstatedir}/kerberos/krb5/user \
 -Wdeprecated ..

%if 0%{?rhel} < 8 && 0%{?fedora} < 31
make VERBOSE=2 %{?_smp_mflags}
%else
%cmake_build
%endif


%install
%if 0%{?rhel} < 9 && 0%{?fedora} < 31
cd build
make install DESTDIR=%{buildroot}
%else
%cmake_install
%endif


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
    checksec --file=%{buildroot}%{_libexecdir}/kcron/${code}
    if [[ $? -ne 0 ]]; then
      exit 1
    fi

    checksec --fortify-file=%{buildroot}%{_libexecdir}/kcron/${code}
    if [[ $? -ne 0 ]]; then
      exit 1
    fi
done
%endif

%post
%{__mkdir_p} --mode=0755 %{_localstatedir}/kerberos/krb5/user
%{__chmod} 0751 %{_localstatedir}/kerberos/krb5/user

%files
%defattr(0644,root,root,0755)
%doc %{_mandir}/man1/*
%attr(0755,root,root) %{_bindir}/*
%config(noreplace) %{_sysconfdir}/sysconfig/kcron
%attr(0755,root,root) /usr/libexec/kcron/client-keytab-name

%if %{with libcap}
# If you can edit the memory this allocates, you can redirect the caps
#  so we still suid to prevent this. user 'bin' is basically unusable anyway.
%attr(4711,bin,root) %caps(cap_chown=p cap_dac_override=p) %{_libexecdir}/kcron/init-kcron-keytab
%else
%attr(4711,root,root) %{_libexecdir}/kcron/init-kcron-keytab
%endif


%changelog

