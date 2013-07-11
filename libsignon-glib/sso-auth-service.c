/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
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
#include "signon-internals.h"
#include "sso-auth-service.h"

static GHashTable *thread_objects = NULL;
static GMutex map_mutex;

static SsoAuthService *
get_singleton ()
{
    SsoAuthService *object = NULL;

    g_mutex_lock (&map_mutex);

    if (thread_objects != NULL)
    {
        GWeakRef *ref;
        ref = g_hash_table_lookup (thread_objects, g_thread_self ());
        if (ref != NULL)
        {
            object = g_weak_ref_get (ref);
        }
    }

    g_mutex_unlock (&map_mutex);
    return object;
}

static void
set_singleton (SsoAuthService *object)
{
    g_return_if_fail (IS_SSO_AUTH_SERVICE (object));

    g_mutex_lock (&map_mutex);

    if (thread_objects == NULL)
    {
        thread_objects = g_hash_table_new (g_direct_hash, g_direct_equal);
    }

    if (object != NULL)
    {
        GWeakRef *ref = g_slice_new (GWeakRef);
        g_weak_ref_init (ref, object);
        g_hash_table_insert (thread_objects, g_thread_self (), ref);
    }

    g_mutex_unlock (&map_mutex);
}

SsoAuthService *
sso_auth_service_get_instance ()
{
    SsoAuthService *sso_auth_service;
    GError *error = NULL;

    sso_auth_service = get_singleton ();
    if (sso_auth_service != NULL) return sso_auth_service;

    /* Create the object */
    sso_auth_service =
        sso_auth_service_proxy_new_for_bus_sync (G_BUS_TYPE_SESSION,
                                                 G_DBUS_PROXY_FLAGS_NONE,
                                                 SIGNOND_SERVICE,
                                                 SIGNOND_DAEMON_OBJECTPATH,
                                                 NULL,
                                                 &error);
    if (G_LIKELY (error == NULL)) {
        set_singleton (sso_auth_service);
    }
    else
    {
        g_warning ("Couldn't activate signond: %s", error->message);
        g_clear_error (&error);
    }

    /* While at it, register the error mapping with GDBus */
    signon_error_quark ();

    return sso_auth_service;
}
