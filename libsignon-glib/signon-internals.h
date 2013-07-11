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

#ifndef _SIGNONINTERNALS_H_
#define _SIGNONINTERNALS_H_

#ifndef SIGNON_TRACE
#define SIGNON_TRACE
#endif

#ifdef SIGNON_TRACE
    #define DEBUG(format...) g_debug (G_STRLOC ": " format)
#else
    #define DEBUG(...) do {} while (0)
#endif

#include <signoncommon.h>

#include "signon-identity.h"
#include "signon-auth-session.h"

G_BEGIN_DECLS

struct _SignonIdentityInfo
{
    gint id;
    gchar *username;
    gchar *secret;
    gchar *caption;
    gboolean store_secret;
    GHashTable *methods;
    gchar **realms;
    gchar **access_control_list;
    gint type;
};

G_GNUC_INTERNAL
SignonIdentityInfo *
signon_identity_info_new_from_variant (GVariant *variant);

G_GNUC_INTERNAL
GVariant *
signon_identity_info_to_variant (const SignonIdentityInfo *self);

G_GNUC_INTERNAL
void signon_identity_info_set_methods (SignonIdentityInfo *self,
                                       const GHashTable *methods);

G_GNUC_INTERNAL
void signon_auth_session_set_id(SignonAuthSession* self,
                                gint32 id);

G_END_DECLS

#endif

