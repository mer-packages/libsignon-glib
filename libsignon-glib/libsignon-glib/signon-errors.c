/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2012 Canonical Ltd.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@canonical.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include "signon-errors.h"
#include "signon-enum-types.h"
#include "signon-internals.h"
#include "signoncommon.h"
#include <gio/gio.h>

/**
 * SECTION:signon-errors
 * @title: SignonError
 * @short_description: Possible errors from Signon.
 *
 * An enumeration of errors that are possible from Signon.
 */
#define SIGNON_ERROR_PREFIX SIGNOND_SERVICE_PREFIX ".Error"

#include "signon-errors-map.c"

GQuark signon_error_quark (void)
{
    static volatile gsize quark = 0;

    g_dbus_error_register_error_domain ("signon-errors",
                                        &quark,
                                        signon_error_entries,
                                        G_N_ELEMENTS (signon_error_entries));
    return (GQuark) quark;
}
