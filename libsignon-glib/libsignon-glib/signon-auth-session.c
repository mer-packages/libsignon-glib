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

/**
 * SECTION:signon-auth-session
 * @title: SignonAuthSession
 * @short_description: Authentication session handler.
 *
 * The #SignonAuthSession object is responsible for handling the client
 * authentication. #SignonAuthSession objects can be created from existing
 * identities (via signon_identity_create_session() or by passing a non-zero ID
 * to signon_auth_session_new()), in which case the authentication data such as
 * username and password will be implicitly taken from the identity, or they
 * can be created with no existing identity bound to them, in which case all
 * the authentication data must be filled in by the client when
 * signon_auth_session_process() is called.
 */

#include "signon-internals.h"
#include "signon-auth-session.h"
#include "signon-dbus-queue.h"
#include "signon-errors.h"
#include "signon-marshal.h"
#include "signon-utils.h"
#include "sso-auth-service.h"
#include "sso-auth-session-gen.h"

/* SignonAuthSessionState is defined in signoncommon.h */
#include <signoncommon.h>

G_DEFINE_TYPE (SignonAuthSession, signon_auth_session, G_TYPE_OBJECT);

/* Signals */
enum
{
    STATE_CHANGED,

    LAST_SIGNAL
};

static guint auth_session_signals[LAST_SIGNAL] = { 0 };
static gchar auth_session_process_pending_message[] = "The request is added to queue.";

struct _SignonAuthSessionPrivate
{
    SsoAuthSession *proxy;
    SsoAuthService *auth_service_proxy;
    GCancellable *cancellable;

    gint id;
    gchar *method_name;

    gboolean registering;
    gboolean busy;
    gboolean canceled;
    gboolean dispose_has_run;

    guint signal_state_changed;
    guint signal_unregistered;
};

typedef struct _AuthSessionQueryAvailableMechanismsData
{
    gchar **wanted_mechanisms;
    gpointer cb_data;
} AuthSessionQueryAvailableMechanismsData;

typedef struct _AuthSessionProcessData
{
    GVariant *session_data;
    gchar *mechanism;
    gpointer cb_data;
} AuthSessionProcessData;

typedef struct _AuthSessionQueryAvailableMechanismsCbData
{
    SignonAuthSession *self;
    SignonAuthSessionQueryAvailableMechanismsCb cb;
    gpointer user_data;
} AuthSessionQueryAvailableMechanismsCbData;

typedef struct _AuthSessionProcessCbData
{
    SignonAuthSession *self;
    SignonAuthSessionProcessCb cb;
    gpointer user_data;
} AuthSessionProcessCbData;

#define SIGNON_AUTH_SESSION_PRIV(obj) (SIGNON_AUTH_SESSION(obj)->priv)
#define SIGNON_AUTH_SESSION_GET_PRIV(obj) (G_TYPE_INSTANCE_GET_PRIVATE ((obj), SIGNON_TYPE_AUTH_SESSION, SignonAuthSessionPrivate))


static void auth_session_state_changed_cb (GDBusProxy *proxy, gint state, gchar *message, gpointer user_data);
static void auth_session_remote_object_destroyed_cb (GDBusProxy *proxy, gpointer user_data);

static gboolean auth_session_priv_init (SignonAuthSession *self, guint id, const gchar *method_name, GError **err);

static void auth_session_set_id_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void auth_session_query_available_mechanisms_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void auth_session_process_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void auth_session_cancel_ready_cb (gpointer object, const GError *error, gpointer user_data);

static void auth_session_check_remote_object(SignonAuthSession *self);

static GQuark
auth_session_object_quark ()
{
  static GQuark quark = 0;

  if (!quark)
    quark = g_quark_from_static_string ("auth_session_object_quark");

  return quark;
}

static void
signon_auth_session_init (SignonAuthSession *self)
{
    self->priv = SIGNON_AUTH_SESSION_GET_PRIV (self);
    self->priv->auth_service_proxy = sso_auth_service_get_instance ();
    self->priv->cancellable = g_cancellable_new ();
}

static void
signon_auth_session_dispose (GObject *object)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    if (priv->dispose_has_run)
        return;

    if (priv->cancellable)
    {
        g_cancellable_cancel (priv->cancellable);
        priv->cancellable = NULL;
    }

    if (priv->proxy)
    {
        g_signal_handler_disconnect (priv->proxy, priv->signal_state_changed);
        g_signal_handler_disconnect (priv->proxy, priv->signal_unregistered);
        g_object_unref (priv->proxy);

        priv->proxy = NULL;
    }

    if (priv->auth_service_proxy)
    {
        g_object_unref (priv->auth_service_proxy);
        priv->auth_service_proxy = NULL;
    }

    G_OBJECT_CLASS (signon_auth_session_parent_class)->dispose (object);

    priv->dispose_has_run = TRUE;
}

static void
signon_auth_session_finalize (GObject *object)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION(object));

    SignonAuthSession *self = SIGNON_AUTH_SESSION(object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    g_free (priv->method_name);

    G_OBJECT_CLASS (signon_auth_session_parent_class)->finalize (object);
}

static void
signon_auth_session_class_init (SignonAuthSessionClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (SignonAuthSessionPrivate));

    /**
     * SignonAuthSession::state-changed:
     *
     * Emitted when the state of the #SignonAuthSession changes.
     */
    auth_session_signals[STATE_CHANGED] =
            g_signal_new ("state-changed",
                          G_TYPE_FROM_CLASS (klass),
                          G_SIGNAL_RUN_LAST | G_SIGNAL_ACTION,
                          0,
                          NULL,
                          NULL,
                          _signon_marshal_VOID__INT_STRING,
                          G_TYPE_NONE, 2,
                          G_TYPE_INT,
                          G_TYPE_STRING);

    object_class->dispose = signon_auth_session_dispose;
    object_class->finalize = signon_auth_session_finalize;
}

/**
 * signon_auth_session_new:
 * @id: the id of the #SignonIdentity to be used. Can be 0, if this session is
 * not bound to any stored identity.
 * @method_name: the name of the authentication method to be used.
 * @err: a pointer to a location which will contain the error, in case this
 * function fails.
 *
 * Creates a new #SignonAuthSession, which can be used to authenticate using
 * the specified method.
 *
 * Returns: a new #SignonAuthSession.
 */
SignonAuthSession *
signon_auth_session_new (gint id,
                         const gchar *method_name,
                         GError **err)
{
    SignonAuthSession *self = SIGNON_AUTH_SESSION(g_object_new (SIGNON_TYPE_AUTH_SESSION, NULL));
    g_return_val_if_fail (self != NULL, NULL);

    if (!auth_session_priv_init(self, id, method_name, err))
    {
        if (*err)
            g_warning ("%s returned error: %s", G_STRFUNC, (*err)->message);

        g_object_unref (self);
        return NULL;
    }

    return self;
}

static void
auth_session_set_id_ready_cb (gpointer object,
                              const GError *error,
                              gpointer user_data)
{
    if (error)
    {
        g_warning ("%s returned error: %s", G_STRFUNC, error->message);
        return;
    }

    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    gint id = GPOINTER_TO_INT(user_data);

    GError *err = NULL;
    sso_auth_session_call_set_id_sync (priv->proxy,
                                       id,
                                       priv->cancellable,
                                       &err);
    priv->id = id;

    if (err)
        g_warning ("%s returned error: %s", G_STRFUNC, err->message);

    g_clear_error(&err);
}

void
signon_auth_session_set_id(SignonAuthSession* self,
                           gint id)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (self));

    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);
    g_return_if_fail (id >= 0);

    auth_session_check_remote_object(self);
    _signon_object_call_when_ready (self,
                                    auth_session_object_quark(),
                                    auth_session_set_id_ready_cb,
                                    GINT_TO_POINTER(id));
}

/**
 * signon_auth_session_get_method:
 * @self: the #SignonAuthSession.
 *
 * Get the current authentication method.
 *
 * Returns: the authentication method being used, or %NULL on failure.
 */
const gchar *
signon_auth_session_get_method (SignonAuthSession *self)
{
    g_return_val_if_fail (SIGNON_IS_AUTH_SESSION (self), NULL);
    SignonAuthSessionPrivate *priv = self->priv;

    g_return_val_if_fail (priv != NULL, NULL);

    return priv->method_name;
}

/**
 * SignonAuthSessionQueryAvailableMechanismsCb:
 * @self: the #SignonAuthSession.
 * @mechanisms: (transfer full) (type GStrv): list of available mechanisms.
 * @error: a #GError if an error occurred, %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * Callback to be passed to signon_auth_session_query_available_mechanisms().
 */

/**
 * signon_auth_session_query_available_mechanisms:
 * @self: the #SignonAuthSession.
 * @wanted_mechanisms: a %NULL-terminated list of mechanisms supported by the client.
 * @cb: (scope async): a callback which will be called with the result.
 * @user_data: user data to be passed to the callback.
 *
 * Queries the mechanisms available for this authentication session. the result
 * will be the intersection between @wanted_mechanisms and the mechanisms
 * supported by the authentication plugin.
 */
void
signon_auth_session_query_available_mechanisms (SignonAuthSession *self,
                                                const gchar **wanted_mechanisms,
                                                SignonAuthSessionQueryAvailableMechanismsCb cb,
                                                gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (self));
    SignonAuthSessionPrivate* priv = self->priv;

    g_return_if_fail (priv != NULL);

    AuthSessionQueryAvailableMechanismsCbData *cb_data = g_slice_new0 (AuthSessionQueryAvailableMechanismsCbData);
    cb_data->self = self;
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    AuthSessionQueryAvailableMechanismsData *operation_data = g_slice_new0 (AuthSessionQueryAvailableMechanismsData);
    operation_data->wanted_mechanisms = g_strdupv ((gchar **)wanted_mechanisms);
    operation_data->cb_data = cb_data;

    auth_session_check_remote_object(self);
    _signon_object_call_when_ready (self,
                                    auth_session_object_quark(),
                                    auth_session_query_available_mechanisms_ready_cb,
                                    operation_data);
}

/**
 * SignonAuthSessionProcessCb:
 * @self: the #SignonAuthSession.
 * @session_data: (transfer full) (element-type utf8 GValue): a dictionary with
 * the response.
 * @error: a #GError if an error occurred, %NULL otherwise.
 * @user_data: the user data that was passed when installing this callback.
 *
 * This callback is invoked when the authentication plugin delivers the result
 * of the signon_auth_session_process() operation.
 */

/**
 * signon_auth_session_process:
 * @self: the #SignonAuthSession.
 * @session_data: (transfer none) (element-type utf8 GValue): a dictionary of parameters.
 * @mechanism: the authentication mechanism to be used.
 * @cb: (scope async): a callback which will be called with the result.
 * @user_data: user data to be passed to the callback.
 *
 * Performs one step of the authentication process. If the #SignonAuthSession
 * object is bound to an existing identity, the identity properties such as
 * username and password will be also passed to the authentication plugin, so
 * there's no need to fill them into @session_data.
 * @session_data can be used to add additional authentication parameters to the
 * session, or to override the parameters otherwise taken from the identity.
 */
void
signon_auth_session_process (SignonAuthSession *self,
                             const GHashTable *session_data,
                             const gchar* mechanism,
                             SignonAuthSessionProcessCb cb,
                             gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (self));
    SignonAuthSessionPrivate *priv = self->priv;

    g_return_if_fail (priv != NULL);
    g_return_if_fail (session_data != NULL);

    AuthSessionProcessCbData *cb_data = g_slice_new0 (AuthSessionProcessCbData);
    cb_data->self = self;
    cb_data->cb = cb;
    cb_data->user_data = user_data;

    AuthSessionProcessData *operation_data = g_slice_new0 (AuthSessionProcessData);

    operation_data->session_data =
        signon_hash_table_to_variant (session_data);
    operation_data->mechanism = g_strdup (mechanism);
    operation_data->cb_data = cb_data;

    priv->busy = TRUE;

    auth_session_check_remote_object(self);
    _signon_object_call_when_ready (self,
                                    auth_session_object_quark(),
                                    auth_session_process_ready_cb,
                                    operation_data);
}

/**
 * signon_auth_session_cancel:
 * @self: the #SignonAuthSession.
 *
 * Cancel the authentication session.
 */
void
signon_auth_session_cancel (SignonAuthSession *self)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (self));
    SignonAuthSessionPrivate *priv = self->priv;

    g_return_if_fail (priv != NULL);

    auth_session_check_remote_object(self);

    if (!priv->busy)
        return;

    priv->canceled = TRUE;
    _signon_object_call_when_ready (self,
                                    auth_session_object_quark(),
                                    auth_session_cancel_ready_cb,
                                    NULL);
}

static void
auth_session_get_object_path_reply (GObject *object, GAsyncResult *res,
                                    gpointer userdata)
{
    SsoAuthService *proxy = SSO_AUTH_SERVICE (object);
    gchar *object_path = NULL;
    GError *error = NULL;

    sso_auth_service_call_get_auth_session_object_path_finish (proxy,
                                                               &object_path,
                                                               res,
                                                               &error);
    SIGNON_RETURN_IF_CANCELLED (error);

    g_return_if_fail (SIGNON_IS_AUTH_SESSION (userdata));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (userdata);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    priv->registering = FALSE;
    if (!g_strcmp0(object_path, "") || error)
    {
        if (error)
            DEBUG ("Error message is %s", error->message);
        else
            error = g_error_new (signon_error_quark(),
                                 SIGNON_ERROR_RUNTIME,
                                 "Cannot create remote AuthSession object");
    }
    else
    {
        GDBusConnection *connection;
        const gchar *bus_name;
        GError *proxy_error = NULL;

        connection = g_dbus_proxy_get_connection ((GDBusProxy *)proxy);
        bus_name = g_dbus_proxy_get_name ((GDBusProxy *)proxy);

        priv->proxy =
            sso_auth_session_proxy_new_sync (connection,
                                             G_DBUS_PROXY_FLAGS_NONE,
                                             bus_name,
                                             object_path,
                                             priv->cancellable,
                                             &proxy_error);
        if (G_UNLIKELY (proxy_error != NULL))
        {
            g_warning ("Failed to initialize AuthSession proxy: %s",
                       proxy_error->message);
            g_clear_error (&proxy_error);
        }

        g_dbus_proxy_set_default_timeout ((GDBusProxy *)priv->proxy,
                                          G_MAXINT);

        priv->signal_state_changed =
            g_signal_connect (priv->proxy,
                              "state-changed",
                              G_CALLBACK (auth_session_state_changed_cb),
                              self);

        priv->signal_unregistered =
           g_signal_connect (priv->proxy,
                             "unregistered",
                             G_CALLBACK (auth_session_remote_object_destroyed_cb),
                             self);
    }

    DEBUG ("Object path received: %s", object_path);
    _signon_object_ready (self, auth_session_object_quark (), error);
    g_clear_error (&error);
}

static void
auth_session_state_changed_cb (GDBusProxy *proxy,
                               gint state,
                               gchar *message,
                               gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (user_data));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (user_data);

    g_signal_emit ((GObject *)self,
                    auth_session_signals[STATE_CHANGED],
                    0,
                    state,
                    message);
}

static void auth_session_remote_object_destroyed_cb (GDBusProxy *proxy,
                                                     gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (user_data));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (user_data);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);
    DEBUG ("remote object unregistered");

    if (priv->proxy)
    {
        g_object_unref (priv->proxy);
        priv->proxy = NULL;
    }

    /*
     * as remote object is destroyed only
     * when the session core is destroyed,
     * so there should not be any processes
     * running
     * */
    priv->busy = FALSE;
    priv->canceled = FALSE;
    _signon_object_not_ready(self);
}

static gboolean
auth_session_priv_init (SignonAuthSession *self, guint id,
                        const gchar *method_name, GError **err)
{
    g_return_val_if_fail (SIGNON_IS_AUTH_SESSION (self), FALSE);
    SignonAuthSessionPrivate *priv = SIGNON_AUTH_SESSION_PRIV (self);
    g_return_val_if_fail (priv, FALSE);

    priv->id = id;
    priv->method_name = g_strdup (method_name);

    priv->registering = TRUE;
    sso_auth_service_call_get_auth_session_object_path (
        priv->auth_service_proxy,
        id,
        method_name,
        priv->cancellable,
        auth_session_get_object_path_reply,
        self);
    priv->busy = FALSE;
    priv->canceled = FALSE;
    return TRUE;
}

static void
auth_session_query_mechanisms_reply (GObject *object, GAsyncResult *res,
                                     gpointer userdata)
{
    SsoAuthSession *proxy = SSO_AUTH_SESSION (object);
    gchar **mechanisms = NULL;
    GError *error = NULL;
    AuthSessionQueryAvailableMechanismsCbData *cb_data =
        (AuthSessionQueryAvailableMechanismsCbData *)userdata;
    g_return_if_fail (cb_data != NULL);

    sso_auth_session_call_query_available_mechanisms_finish (proxy,
                                                             &mechanisms,
                                                             res,
                                                             &error);
    SIGNON_RETURN_IF_CANCELLED (error);
    (cb_data->cb) (cb_data->self, mechanisms, error, cb_data->user_data);

    if (error)
        g_error_free (error);

    g_slice_free (AuthSessionQueryAvailableMechanismsCbData, cb_data);
}

static void
auth_session_process_reply (GObject *object, GAsyncResult *res,
                            gpointer userdata)
{
    SsoAuthSession *proxy = SSO_AUTH_SESSION (object);
    GVariant *session_data_variant;
    GHashTable *session_data = NULL;
    GError *error = NULL;
    AuthSessionProcessCbData *cb_data = (AuthSessionProcessCbData *)userdata;
    g_return_if_fail (cb_data != NULL);
    g_return_if_fail (cb_data->self != NULL);
    g_return_if_fail (cb_data->self->priv != NULL);

    sso_auth_session_call_process_finish (proxy,
                                          &session_data_variant,
                                          res,
                                          &error);
    SIGNON_RETURN_IF_CANCELLED (error);

    if (!error)
    {
        session_data = signon_hash_table_from_variant (session_data_variant);
    }

    /* Keep a reference on the SignonAuthSession, because the callback
     * code might unreference it, while we still need it. */
    g_object_ref (cb_data->self);
    (cb_data->cb) (cb_data->self, session_data, error, cb_data->user_data);

    cb_data->self->priv->busy = FALSE;
    if (error)
        g_error_free (error);

    if (session_data != NULL)
        g_hash_table_unref (session_data);

    g_object_unref (cb_data->self);
    g_slice_free (AuthSessionProcessCbData, cb_data);
}

static void
auth_session_query_available_mechanisms_ready_cb (gpointer object, const GError *error,
                                                  gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));
    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    AuthSessionQueryAvailableMechanismsData *operation_data =
        (AuthSessionQueryAvailableMechanismsData *)user_data;
    g_return_if_fail (operation_data != NULL);

    AuthSessionQueryAvailableMechanismsCbData *cb_data = operation_data->cb_data;
    g_return_if_fail (cb_data != NULL);

    if (error)
    {
        (cb_data->cb)
            (self, NULL, error, cb_data->user_data);

        g_slice_free (AuthSessionQueryAvailableMechanismsCbData, cb_data);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);
        sso_auth_session_call_query_available_mechanisms (
            priv->proxy,
            (const char **)operation_data->wanted_mechanisms,
            priv->cancellable,
            auth_session_query_mechanisms_reply,
            cb_data);

        g_signal_emit (self,
                       auth_session_signals[STATE_CHANGED],
                       0,
                       SIGNON_AUTH_SESSION_STATE_PROCESS_PENDING,
                       auth_session_process_pending_message);
    }

    g_strfreev (operation_data->wanted_mechanisms);
    g_slice_free (AuthSessionQueryAvailableMechanismsData, operation_data);
}

static void
auth_session_process_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));

    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = SIGNON_AUTH_SESSION_PRIV (self);

    AuthSessionProcessData *operation_data =
        (AuthSessionProcessData *)user_data;
    g_return_if_fail (operation_data != NULL);

    AuthSessionProcessCbData *cb_data = operation_data->cb_data;
    g_return_if_fail (cb_data != NULL);

    if (error || priv->canceled)
    {
        GError *err = (error ? (GError *)error :
                       g_error_new (signon_error_quark (),
                                    SIGNON_ERROR_SESSION_CANCELED,
                                    "Authentication session was canceled"));

        DEBUG ("AuthSessionError: %s", err->message);

        (cb_data->cb)
            (self, NULL, err, cb_data->user_data);

        if (!error)
            g_clear_error (&err);

        g_slice_free (AuthSessionProcessCbData, cb_data);

        priv->busy = FALSE;
        priv->canceled = FALSE;
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);

        sso_auth_session_call_process (priv->proxy,
                                       operation_data->session_data,
                                       operation_data->mechanism,
                                       priv->cancellable,
                                       auth_session_process_reply,
                                       cb_data);

       g_signal_emit (self,
                       auth_session_signals[STATE_CHANGED],
                       0,
                       SIGNON_AUTH_SESSION_STATE_PROCESS_PENDING,
                       auth_session_process_pending_message);
    }

    g_free (operation_data->mechanism);
    g_slice_free (AuthSessionProcessData, operation_data);
}

static void
auth_session_cancel_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_AUTH_SESSION (object));
    g_return_if_fail (user_data == NULL);

    SignonAuthSession *self = SIGNON_AUTH_SESSION (object);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    if (error)
    {
        //TODO: in general this function does not return any values,
        // that is why I think it should not emit anything for this particular case
        DEBUG("error during initialization");
    }
    else if (priv->proxy && priv->busy)
        sso_auth_session_call_cancel_sync (priv->proxy,
                                           priv->cancellable,
                                           NULL);

    priv->busy = FALSE;
    priv->canceled = FALSE;
}

static void
auth_session_check_remote_object(SignonAuthSession *self)
{
    g_return_if_fail (self != NULL);
    SignonAuthSessionPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    if (priv->proxy != NULL)
        return;

    g_return_if_fail (priv->auth_service_proxy != NULL);

    if (!priv->registering)
    {
        priv->registering = TRUE;
        sso_auth_service_call_get_auth_session_object_path (
            priv->auth_service_proxy,
            priv->id,
            priv->method_name,
            priv->cancellable,
            auth_session_get_object_path_reply,
            self);
    }
}

