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

#ifndef SIGNONDBUSQUEUEDDATA_H
#define SIGNONDBUSQUEUEDDATA_H

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

typedef void (*SignonReadyCb) (gpointer object, const GError *error,
                               gpointer user_data);

void _signon_object_call_when_ready (gpointer object, GQuark quark,
                                    SignonReadyCb callback, gpointer user_data);

void _signon_object_ready (gpointer object, GQuark quark, const GError *error);
void _signon_object_not_ready (gpointer object);

const GError *_signon_object_last_error (gpointer object);

G_END_DECLS
#endif /* SIGNONDBUSQUEUEDDATA_H */
