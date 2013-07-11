Name: libsignon-glib
Version: 1.7
Release: 1
Summary: GLib wrapper for single signon framework
Group: System/Libraries
License: LGPLv2.1
URL: http://code.google.com/p/accounts-sso/
Source0: http://accounts-sso.googlecode.com/files/libsignon-glib-%{version}.tar.gz
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires: pkgconfig(gio-2.0)
BuildRequires: pkgconfig(gio-unix-2.0)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(gobject-2.0)
BuildRequires: pkgconfig(signond)
BuildRequires: pkgconfig(check)
BuildRequires: python
# For signond
Requires: libsignon

%description
%{summary}.

%files
%defattr(-,root,root,-)
%{_libdir}/libsignon-glib.so.*
%{_datadir}/vala/vapi/signon.vapi
%exclude /usr/doc/reference/*

%package devel
Summary: Development files for libsignon-glib
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
# signond.pc, required by libsignon-glib.pc
Requires: pkgconfig(signond)

%description devel
%{summary}

%files devel
%defattr(-,root,root,-)
%{_libdir}/libsignon-glib.so
%{_includedir}/libsignon-glib/*.h
%{_libdir}/pkgconfig/libsignon-glib.pc

%package docs
Summary: Documentation for libsignon-glib
Group: Documentation

%description docs
%{summary}

%files docs
%defattr(-,root,root,-)
%{_datadir}/gtk-doc/html/libsignon-glib/*

%prep
%setup -q -n %{name}-%{version}/libsignon-glib

%build
%reconfigure
# %{?jobs:-j%jobs} disabled to fix errors with xgen-getc
make

%install
rm -rf %{buildroot}
%make_install

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig
