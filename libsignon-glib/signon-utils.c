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
#include "signon-utils.h"
#include <gio/gio.h>

static const GVariantType *
signon_gtype_to_variant_type (GType type)
{
    switch (type)
    {
    case G_TYPE_STRING: return G_VARIANT_TYPE_STRING;
    case G_TYPE_BOOLEAN: return G_VARIANT_TYPE_BOOLEAN;
    case G_TYPE_UCHAR: return G_VARIANT_TYPE_BYTE;
    case G_TYPE_INT: return G_VARIANT_TYPE_INT32;
    case G_TYPE_UINT: return G_VARIANT_TYPE_UINT32;
    case G_TYPE_INT64: return G_VARIANT_TYPE_INT64;
    case G_TYPE_UINT64: return G_VARIANT_TYPE_UINT64;
    case G_TYPE_DOUBLE: return G_VARIANT_TYPE_DOUBLE;
    default:
        if (type == G_TYPE_STRV) return G_VARIANT_TYPE_STRING_ARRAY;

        g_critical ("Unsupported type %s", g_type_name (type));
        return NULL;
    }
}

GValue *
signon_gvalue_new (GType type)
{
    GValue *value = g_slice_new0 (GValue);
    g_value_init (value, type);
    return value;
}

void signon_gvalue_free (gpointer val)
{
    g_return_if_fail (G_IS_VALUE(val));

    GValue *value = (GValue*)val;
    g_value_unset (value);
    g_slice_free (GValue, value);
}

GHashTable *signon_hash_table_from_variant (GVariant *variant)
{
    GHashTable *hash_table;
    GVariantIter iter;
    GVariant *value;
    gchar *key;

    if (variant == NULL) return NULL;

    hash_table = g_hash_table_new_full (g_str_hash,
                                        g_str_equal,
                                        g_free,
                                        signon_gvalue_free);
    g_variant_iter_init (&iter, variant);
    while (g_variant_iter_next (&iter, "{sv}", &key, &value))
    {
        GValue *val = g_slice_new0 (GValue);
        g_dbus_gvariant_to_gvalue (value, val);
        g_variant_unref (value);

        g_hash_table_insert (hash_table, key, val);
    }
    return hash_table;
}

GVariant *signon_hash_table_to_variant (const GHashTable *hash_table)
{
    GVariantBuilder builder;
    GHashTableIter iter;
    const gchar *key;
    const GValue *value;

    if (hash_table == NULL) return NULL;

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

    g_hash_table_iter_init (&iter, (GHashTable *)hash_table);
    while (g_hash_table_iter_next (&iter, (gpointer)&key, (gpointer)&value))
    {
        GVariant *val;

        if (G_VALUE_TYPE (value) == G_TYPE_VARIANT)
        {
            val = g_value_get_variant (value);
        }
        else
        {
            const GVariantType *type;
            type = signon_gtype_to_variant_type (G_VALUE_TYPE (value));
            val = g_dbus_gvalue_to_gvariant (value, type);
        }
        g_variant_builder_add (&builder, "{sv}", key, val);
    }
    return g_variant_builder_end (&builder);
}
