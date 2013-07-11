/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2011-2012 Canonical Ltd.
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

/**
 * SECTION:signon-identity-info
 * @title: SignonIdentityInfo
 * @short_description: Extra data for a #SignonIdentity.
 *
 * Extra data retreived from a #SignonIdentity.
 */

#include "signon-identity-info.h"

#include "signon-internals.h"
#include "signon-utils.h"

G_DEFINE_BOXED_TYPE (SignonIdentityInfo, signon_identity_info,
                     (GBoxedCopyFunc)signon_identity_info_copy,
                     (GBoxedFreeFunc)signon_identity_info_free);


static GVariant *
signon_variant_new_string (const gchar *string)
{
    return g_variant_new_string (string != NULL ? string : "");
}

static const gchar *identity_info_get_secret (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);

    return info->secret;
}

static void identity_info_set_id (SignonIdentityInfo *info, gint id)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (id >= 0);

    info->id = id;
}

static void identity_methods_copy (gpointer key, gpointer value, gpointer user_data)
{
    signon_identity_info_set_method ((SignonIdentityInfo *)user_data,
                                     (const gchar *)key,
                                     (const gchar* const *)value);
}

void signon_identity_info_set_methods (SignonIdentityInfo *info,
                                       const GHashTable *methods)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (methods != NULL);

    DEBUG("%s", G_STRFUNC);

    if (info->methods)
        g_hash_table_remove_all (info->methods);
    else
        info->methods = g_hash_table_new_full (g_str_hash, g_str_equal,
                                               g_free, (GDestroyNotify)g_strfreev);

    g_hash_table_foreach ((GHashTable *)methods, identity_methods_copy, info);
}

SignonIdentityInfo *
signon_identity_info_new_from_variant (GVariant *variant)
{
    GVariant *method_map;

    if (!variant)
        return NULL;

    SignonIdentityInfo *info = signon_identity_info_new ();

    DEBUG("%s: ", G_STRFUNC);

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_ID,
                      "u",
                      &info->id);

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_USERNAME,
                      "s",
                      &info->username);

    if (g_variant_lookup (variant,
                          SIGNOND_IDENTITY_INFO_SECRET,
                          "s",
                          &info->secret))
    {
        g_variant_lookup (variant,
                          SIGNOND_IDENTITY_INFO_STORESECRET,
                          "b",
                          &info->store_secret);
    }

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_CAPTION,
                      "s",
                      &info->caption);

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_REALMS,
                      "^as",
                      &info->realms);

    /* get the methods */
    if (g_variant_lookup (variant,
                          SIGNOND_IDENTITY_INFO_AUTHMETHODS,
                          "@a{sas}",
                          &method_map))
    {
        GVariantIter iter;
        gchar *method;
        gchar **mechanisms;

        g_variant_iter_init (&iter, method_map);
        while (g_variant_iter_next (&iter, "{s^as}", &method, &mechanisms))
        {
            g_hash_table_insert (info->methods, method, mechanisms);
        }
    }

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_ACL,
                      "^as",
                      &info->access_control_list);

    g_variant_lookup (variant,
                      SIGNOND_IDENTITY_INFO_TYPE,
                      "u",
                      &info->type);

    return info;
}

GVariant *
signon_identity_info_to_variant (const SignonIdentityInfo *self)
{
    GVariantBuilder builder;
    GVariantBuilder method_builder;
    GVariant *method_map;
    GHashTableIter iter;
    const gchar *method;
    const gchar **mechanisms;

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

    g_variant_builder_add (&builder, "{sv}",
                           SIGNOND_IDENTITY_INFO_ID,
                           g_variant_new_uint32 (self->id));

    g_variant_builder_add (&builder, "{sv}",
                           SIGNOND_IDENTITY_INFO_USERNAME,
                           signon_variant_new_string (self->username));

    g_variant_builder_add (&builder, "{sv}",
                           SIGNOND_IDENTITY_INFO_SECRET,
                           signon_variant_new_string (self->secret));

    g_variant_builder_add (&builder, "{sv}",
                           SIGNOND_IDENTITY_INFO_CAPTION,
                           signon_variant_new_string (self->caption));

    g_variant_builder_add (&builder, "{sv}",
                           SIGNOND_IDENTITY_INFO_STORESECRET,
                           g_variant_new_boolean (self->store_secret));

    g_variant_builder_init (&method_builder,
                            (const GVariantType *)"a{sas}");
    g_hash_table_iter_init (&iter, self->methods);
    while (g_hash_table_iter_next (&iter,
                                   (gpointer)&method,
                                   (gpointer)&mechanisms))
    {
        g_variant_builder_add (&method_builder, "{s^as}",
                               method,
                               mechanisms);
    }
    method_map = g_variant_builder_end (&method_builder);

    g_variant_builder_add (&builder, "{sv}",
                           SIGNOND_IDENTITY_INFO_AUTHMETHODS,
                           method_map);

    if (self->realms != NULL)
    {
        g_variant_builder_add (&builder, "{sv}",
                               SIGNOND_IDENTITY_INFO_REALMS,
                               g_variant_new_strv ((const gchar * const *)
                                                   self->realms,
                                                   -1));
    }

    if (self->access_control_list != NULL)
    {
        g_variant_builder_add (&builder, "{sv}",
                               SIGNOND_IDENTITY_INFO_ACL,
                               g_variant_new_strv ((const gchar * const *)
                                                   self->access_control_list,
                                                   -1));
    }

    g_variant_builder_add (&builder, "{sv}",
                           SIGNOND_IDENTITY_INFO_TYPE,
                           g_variant_new_int32 (self->type));

    return g_variant_builder_end (&builder);
}

/*
 * Public methods:
 */

/**
 * signon_identity_info_new:
 *
 * Creates a new #SignonIdentityInfo item.
 *
 * Returns: a new #SignonIdentityInfo item.
 */
SignonIdentityInfo *signon_identity_info_new ()
{
    SignonIdentityInfo *info = g_slice_new0 (SignonIdentityInfo);
    info->methods = g_hash_table_new_full (g_str_hash, g_str_equal,
                                            g_free, (GDestroyNotify)g_strfreev);
    info->store_secret = FALSE;

    return info;
}

/**
 * signon_identity_info_free:
 * @info: the #SignonIdentityInfo.
 *
 * Destroys the given #SignonIdentityInfo item.
 */
void signon_identity_info_free (SignonIdentityInfo *info)
{
    if (info == NULL) return;

    g_free (info->username);
    g_free (info->secret);
    g_free (info->caption);

    g_hash_table_destroy (info->methods);

    g_strfreev (info->realms);
    g_strfreev (info->access_control_list);

    g_slice_free (SignonIdentityInfo, info);
}

/**
 * signon_identity_info_copy:
 * @other: the #SignonIdentityInfo.
 *
 * Get a newly-allocated copy of @info.
 *
 * Returns: a copy of the given #SignonIdentityInfo, or %NULL on failure.
 */
SignonIdentityInfo *signon_identity_info_copy (const SignonIdentityInfo *other)
{
    g_return_val_if_fail (other != NULL, NULL);
    SignonIdentityInfo *info = signon_identity_info_new ();

    identity_info_set_id (info, signon_identity_info_get_id (other));

    signon_identity_info_set_username (info, signon_identity_info_get_username (other));

    signon_identity_info_set_secret (info, identity_info_get_secret(other),
                                     signon_identity_info_get_storing_secret (other));

    signon_identity_info_set_caption (info, signon_identity_info_get_caption(other));

    signon_identity_info_set_methods (info, signon_identity_info_get_methods (other));

    signon_identity_info_set_realms (info, signon_identity_info_get_realms (other));

    signon_identity_info_set_access_control_list (info,
        signon_identity_info_get_access_control_list (other));

    signon_identity_info_set_identity_type (info,
        signon_identity_info_get_identity_type (other));

    return info;
}

/**
 * signon_identity_info_get_id:
 * @info: the #SignonIdentityInfo.
 *
 * Get the numeric ID of @info.
 *
 * Returns: the numeric ID of the identity.
 */
gint signon_identity_info_get_id (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, -1);
    return info->id;
}

/**
 * signon_identity_info_get_username:
 * @info: the #SignonIdentityInfo.
 *
 * Get the username of @info.
 *
 * Returns: the username, or %NULL.
 */
const gchar *signon_identity_info_get_username (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->username;
}

/**
 * signon_identity_info_get_storing_secret:
 * @info: the #SignonIdentityInfo.
 *
 * Get whether the secret of @info should be stored.
 *
 * Returns: %TRUE if Signon must store the secret, %FALSE otherwise.
 */
gboolean signon_identity_info_get_storing_secret (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, FALSE);
    return info->store_secret;
}

/**
 * signon_identity_info_get_caption:
 * @info: the #SignonIdentityInfo.
 *
 * Get the display name of @info.
 *
 * Returns: the display name for the identity.
 */
const gchar *signon_identity_info_get_caption (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->caption;
}

/**
 * signon_identity_info_get_methods:
 * @info: the #SignonIdentityInfo.
 *
 * Get a hash table of the methods and mechanisms of @info.
 *
 * Returns: (transfer none) (element-type utf8 GStrv): the table of allowed
 * methods and mechanisms.
 */
const GHashTable *signon_identity_info_get_methods (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return info->methods;
}

/**
 * signon_identity_info_get_realms:
 * @info: the #SignonIdentityInfo.
 *
 * Get an array of the realms of @info.
 *
 * Returns: (transfer none): a %NULL terminated array of realms.
 */
const gchar* const *signon_identity_info_get_realms (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return (const gchar* const *)info->realms;
}

/**
 * signon_identity_info_get_access_control_list:
 * @info: the #SignonIdentityInfo.
 *
 * Get an array of ACL statements of the identity.
 *
 * Returns: (transfer none): a %NULL terminated array of ACL statements.
 */
const gchar* const *signon_identity_info_get_access_control_list (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, NULL);
    return (const gchar* const *)info->access_control_list;
}

/**
 * signon_identity_info_get_identity_type:
 * @info: the #SignonIdentityInfo.
 *
 * Get the type of the identity.
 *
 * Returns: the type of the identity.
 */
SignonIdentityType signon_identity_info_get_identity_type (const SignonIdentityInfo *info)
{
    g_return_val_if_fail (info != NULL, -1);
    return (SignonIdentityType)info->type;
}

/**
 * signon_identity_info_set_username:
 * @info: the #SignonIdentityInfo.
 * @username: the username.
 *
 * Sets the username for the identity.
 */
void signon_identity_info_set_username (SignonIdentityInfo *info, const gchar *username)
{
    g_return_if_fail (info != NULL);

    if (info->username) g_free (info->username);

    info->username = g_strdup (username);
}

/**
 * signon_identity_info_set_secret:
 * @info: the #SignonIdentityInfo.
 * @secret: the secret.
 * @store_secret: whether signond should store the secret in its DB.
 *
 * Sets the secret (password) for the identity, and whether the signon daemon
 * should remember it.
 */
void signon_identity_info_set_secret (SignonIdentityInfo *info, const gchar *secret,
                                      gboolean store_secret)
{
    g_return_if_fail (info != NULL);

    if (info->secret) g_free (info->secret);

    info->secret = g_strdup (secret);
    info->store_secret = store_secret;
}

/**
 * signon_identity_info_set_caption:
 * @info: the #SignonIdentityInfo.
 * @caption: the caption.
 *
 * Sets the caption (display name) for the identity.
 */
void signon_identity_info_set_caption (SignonIdentityInfo *info, const gchar *caption)
{
    g_return_if_fail (info != NULL);

    if (info->caption) g_free (info->caption);

    info->caption = g_strdup (caption);
}

/**
 * signon_identity_info_set_method:
 * @info: the #SignonIdentityInfo.
 * @method: an authentication method.
 * @mechanisms: a %NULL-termianted list of mechanisms.
 *
 * Adds a method to the list of allowed methods. If this method is not called
 * even once, then all methods are allowed.
 * Mechanisms are method-specific variants of authentication.
 */
void signon_identity_info_set_method (SignonIdentityInfo *info, const gchar *method,
                                      const gchar* const *mechanisms)
{
    g_return_if_fail (info != NULL);

    g_return_if_fail (info->methods != NULL);
    g_return_if_fail (method != NULL);
    g_return_if_fail (mechanisms != NULL);

    g_hash_table_replace (info->methods,
                          g_strdup(method), g_strdupv((gchar **)mechanisms));
}

/**
 * signon_identity_info_remove_method:
 * @info: the #SignonIdentityInfo.
 * @method: an authentication method.
 *
 * Remove @method from the list of allowed authentication methods. If all
 * methods are removed, then all methods are allowed.
 */
void signon_identity_info_remove_method (SignonIdentityInfo *info, const gchar *method)
{
    g_return_if_fail (info != NULL);
    g_return_if_fail (info->methods != NULL);

    g_hash_table_remove (info->methods, method);
}

/**
 * signon_identity_info_set_realms:
 * @info: the #SignonIdentityInfo.
 * @realms: a %NULL-terminated list of realms.
 *
 * Specify what realms this identity can be used in.
 */
void signon_identity_info_set_realms (SignonIdentityInfo *info,
                                      const gchar* const *realms)
{
    g_return_if_fail (info != NULL);

    if (info->realms) g_strfreev (info->realms);

    info->realms = g_strdupv ((gchar **)realms);
}

/**
 * signon_identity_info_set_access_control_list:
 * @info: the #SignonIdentityInfo.
 * @access_control_list: a %NULL-terminated list of ACL security domains.
 *
 * Specifies the ACL for this identity. The actual meaning of the ACL depends
 * on the security framework used by signond.
 */
void signon_identity_info_set_access_control_list (SignonIdentityInfo *info,
                                                   const gchar* const *access_control_list)
{
    g_return_if_fail (info != NULL);

    if (info->access_control_list) g_strfreev (info->access_control_list);

    info->access_control_list = g_strdupv ((gchar **)access_control_list);
}

/**
 * signon_identity_info_set_identity_type:
 * @info: the #SignonIdentityInfo.
 * @type: the type of the identity.
 *
 * Specifies the type of this identity.
 */
void signon_identity_info_set_identity_type (SignonIdentityInfo *info,
                                             SignonIdentityType type)
{
    g_return_if_fail (info != NULL);
    info->type = (gint)type;
}
