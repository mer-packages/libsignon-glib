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
#ifndef _SIGNON_UTILS_H_
#define _SIGNON_UTILS_H_

#include <glib-object.h>

#define SIGNON_RETURN_IF_CANCELLED(error) \
    if (error != NULL && \
        error->domain == G_IO_ERROR && \
        error->code == G_IO_ERROR_CANCELLED) \
    { \
        g_error_free (error); \
        return; \
    }

G_GNUC_INTERNAL
GValue *signon_gvalue_new (GType type);
G_GNUC_INTERNAL
void signon_gvalue_free (gpointer val);

G_GNUC_INTERNAL
GHashTable *signon_hash_table_from_variant (GVariant *variant);
G_GNUC_INTERNAL
GVariant *signon_hash_table_to_variant (const GHashTable *hash_table);

#endif //_SIGNON_UTILS_H_
