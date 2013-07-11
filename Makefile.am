ACLOCAL_AMFLAGS = -I m4
DISTCHECK_CONFIGURE_FLAGS = \
	--enable-gtk-doc \
	--enable-introspection=yes
SUBDIRS = libsignon-glib docs tests

if ENABLE_PYTHON
SUBDIRS += pygobject
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsignon-glib.pc

libsignondocdir = ${prefix}/doc/reference
libsignondoc_DATA= README COPYING AUTHORS ChangeLog INSTALL NEWS

EXTRA_DIST = \
	$(libsignondoc_DATA) \
	m4/introspection.m4
