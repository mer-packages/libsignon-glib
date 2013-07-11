/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@nokia.com>
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

#include "signon-dbus-queue.h"

typedef struct {
    SignonReadyCb callback;
    gpointer user_data;
} SignonReadyCbData;

typedef struct {
    gpointer self;
    GSList *callbacks;
} SignonReadyData;

static GQuark
_signon_object_ready_quark()
{
  static GQuark quark = 0;

  if (!quark)
    quark = g_quark_from_static_string ("signon_object_ready_quark");

  return quark;
}

static GQuark
_signon_object_error_quark()
{
  static GQuark quark = 0;

  if (!quark)
    quark = g_quark_from_static_string ("signon_object_error_quark");

  return quark;
}

static void
signon_object_invoke_ready_callbacks (SignonReadyData *rd, const GError *error)
{
    GSList *list;

    for (list = rd->callbacks; list != NULL; list = list->next)
    {
        SignonReadyCbData *cb = list->data;

        cb->callback (rd->self, error, cb->user_data);
        g_slice_free (SignonReadyCbData, cb);
    }
    g_slist_free (rd->callbacks);
}

static void
signon_ready_data_free (SignonReadyData *rd)
{
    if (rd->self)
    {
        //TODO: Signon error codes need be presented instead of 555 and 666
        GError error = { 555, 666, "Object disposed" };
        signon_object_invoke_ready_callbacks (rd, &error);
    }
    g_slice_free (SignonReadyData, rd);
}

void
_signon_object_call_when_ready (gpointer object, GQuark quark, SignonReadyCb callback,
                                gpointer user_data)
{
    SignonReadyData *rd;
    SignonReadyCbData *cb;

    g_return_if_fail (G_IS_OBJECT (object));
    g_return_if_fail (quark != 0);
    g_return_if_fail (callback != NULL);

    if (GPOINTER_TO_INT (g_object_get_qdata((GObject *)object,
                           _signon_object_ready_quark())) == TRUE)
    {
        //TODO: specify the last error in object initialization
        GError * err = g_object_get_qdata((GObject *)object,
                                          _signon_object_error_quark());
        return (*callback)(object, err, user_data);
    }

    cb = g_slice_new (SignonReadyCbData);
    cb->callback = callback;
    cb->user_data = user_data;

    rd = g_object_get_qdata ((GObject *)object, quark);
    if (!rd)
    {
        rd = g_slice_new (SignonReadyData);
        rd->self = object;
        rd->callbacks = NULL;
        g_object_set_qdata_full ((GObject *)object, quark, rd,
                                 (GDestroyNotify)signon_ready_data_free);
    }

    rd->callbacks = g_slist_append (rd->callbacks, cb);
}

void
_signon_object_ready (gpointer object, GQuark quark, const GError *error)
{
    SignonReadyData *rd;

    g_object_set_qdata((GObject *)object, _signon_object_ready_quark(), GINT_TO_POINTER(TRUE));

    if(error)
        g_object_set_qdata_full ((GObject *)object, _signon_object_error_quark(),
                                  g_error_copy(error),
                                 (GDestroyNotify)g_error_free);

    /* steal the qdata so the callbacks won't be invoked again, even if the
     * object becomes ready or is finalized while still invoking them */

    rd = g_object_steal_qdata ((GObject *)object, quark);
    if (!rd) return;

    g_object_ref (object);

    signon_object_invoke_ready_callbacks (rd, error);
    rd->self = NULL; /* so the callbacks won't be invoked again */
    signon_ready_data_free (rd);

    g_object_unref (object);

    //TODO: set some sort of ready information
}

void
_signon_object_not_ready (gpointer object)
{
    g_object_set_qdata ((GObject *)object,
                        _signon_object_ready_quark(),
                        GINT_TO_POINTER(FALSE));

    g_object_set_qdata ((GObject *)object,
                        _signon_object_error_quark(),
                        NULL);
}

const GError *
_signon_object_last_error (gpointer object)
{
    return g_object_get_qdata((GObject *)object,
                              _signon_object_error_quark());
}
