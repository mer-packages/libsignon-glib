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

#ifndef _SIGNON_AUTH_SERVICE_H_
#define _SIGNON_AUTH_SERVICE_H_

#include <glib-object.h>

G_BEGIN_DECLS

#define SIGNON_TYPE_AUTH_SERVICE             (signon_auth_service_get_type ())
#define SIGNON_AUTH_SERVICE(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), SIGNON_TYPE_AUTH_SERVICE, SignonAuthService))
#define SIGNON_AUTH_SERVICE_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), SIGNON_TYPE_AUTH_SERVICE, SignonAuthServiceClass))
#define SIGNON_IS_AUTH_SERVICE(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SIGNON_TYPE_AUTH_SERVICE))
#define SIGNON_IS_AUTH_SERVICE_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), SIGNON_TYPE_AUTH_SERVICE))
#define SIGNON_AUTH_SERVICE_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), SIGNON_TYPE_AUTH_SERVICE, SignonAuthServiceClass))

typedef struct _SignonAuthServiceClass SignonAuthServiceClass;
typedef struct _SignonAuthServicePrivate SignonAuthServicePrivate;
typedef struct _SignonAuthService SignonAuthService;

/**
 * SignonAuthServiceClass:
 *
 * Opaque struct. Use the accessor functions below.
 */
struct _SignonAuthServiceClass
{
    GObjectClass parent_class;
};

/**
 * SignonAuthService:
 *
 * Opaque struct. Use the accessor functions below.
 */
struct _SignonAuthService
{
    GObject parent_instance;
    SignonAuthServicePrivate *priv;
};

GType signon_auth_service_get_type (void) G_GNUC_CONST;

typedef void (*SignonQueryMethodsCb) (SignonAuthService *auth_service,
                                      gchar **methods,
                                      const GError *error,
                                      gpointer user_data);

typedef void (*SignonQueryMechanismCb) (SignonAuthService *auth_service,
                                        const gchar *method,
                                        gchar **mechanisms,
                                        const GError *error,
                                        gpointer user_data);

SignonAuthService *signon_auth_service_new ();

void signon_auth_service_query_methods (SignonAuthService *auth_service,
                                        SignonQueryMethodsCb cb,
                                        gpointer user_data);
void signon_auth_service_query_mechanisms (SignonAuthService *auth_service,
                                           const gchar *method,
                                           SignonQueryMechanismCb cb,
                                           gpointer user_data);
G_END_DECLS

#endif /* _SIGNON_AUTH_SERVICE_H_ */
