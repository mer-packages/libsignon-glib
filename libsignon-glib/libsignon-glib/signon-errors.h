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

#ifndef __LIBSIGNON_ERRORS_H__
#define __LIBSIGNON_ERRORS_H__

#include <glib.h>
#include <glib-object.h>
#include "signon-enum-types.h"

#define SIGNON_ERROR (signon_error_quark())

/**
 * SignonError:
 * @SIGNON_ERROR_UNKNOWN: Catch-all for errors not distinguished by another code.
 * @SIGNON_ERROR_INTERNAL_SERVER: Signon daemon internal error.
 * @SIGNON_ERROR_INTERNAL_COMMUNICATION: Error communicating with Sigon daemon.
 * @SIGNON_ERROR_PERMISSION_DENIED: The operation cannot be performed due to
 * insufficient client permissions.
 * @SIGNON_ERROR_METHOD_NOT_KNOWN: The method with this name was not found.
 * @SIGNON_ERROR_SERVICE_NOT_AVAILABLE: The service is temporarily unavailable.
 * @SIGNON_ERROR_INVALID_QUERY: Parameters for the query are invalid.
 * @SIGNON_ERROR_METHOD_NOT_AVAILABLE: The requested method is not available.
 * @SIGNON_ERROR_IDENTITY_NOT_FOUND: The identity mathching the #SignonIdentity
 * was not found on the service.
 * @SIGNON_ERROR_STORE_FAILED: Storing credentials failed.
 * @SIGNON_ERROR_REMOVE_FAILED: Removing credentials failed.
 * @SIGNON_ERROR_SIGNOUT_FAILED: Signing out failed.
 * @SIGNON_ERROR_IDENTITY_OPERATION_CANCELED: Identity operation was canceled
 * by the user.
 * @SIGNON_ERROR_CREDENTIALS_NOT_AVAILABLE: Query failed.
 * @SIGNON_ERROR_REFERENCE_NOT_FOUND: Trying to remove non-existent reference.
 * @SIGNON_ERROR_MECHANISM_NOT_AVAILABLE: The requested mechanism in not
 * available.
 * @SIGNON_ERROR_MISSING_DATA: The #SessionData does not contain the necessary
 * information.
 * @SIGNON_ERROR_INVALID_CREDENTIALS: The supplied credentials are invalid for
 * the mechanism implementation.
 * @SIGNON_ERROR_NOT_AUTHORIZED: Authorization failed.
 * @SIGNON_ERROR_WRONG_STATE: An operation method has been called in an
 * incorrect state.
 * @SIGNON_ERROR_OPERATION_NOT_SUPPORTED: The operation is not supported by the
 * mechanism implementation.
 * @SIGNON_ERROR_NO_CONNECTION: No network connection.
 * @SIGNON_ERROR_NETWORK: Network connection failed.
 * @SIGNON_ERROR_SSL: SSL connection failed.
 * @SIGNON_ERROR_RUNTIME: Casting #SessionData into subclass failed.
 * @SIGNON_ERROR_SESSION_CANCELED: Challenge was canceled.
 * @SIGNON_ERROR_TIMED_OUT: Challenge timed out.
 * @SIGNON_ERROR_USER_INTERACTION: User interaction dialog failed.
 * @SIGNON_ERROR_OPERATION_FAILED: Temporary failure in authentication.
 * @SIGNON_ERROR_ENCRYPTION_FAILED: @deprecated: Failure during data
 * encryption/decryption.
 * @SIGNON_ERROR_TOS_NOT_ACCEPTED: User declined Terms of Service.
 * @SIGNON_ERROR_FORGOT_PASSWORD: User requested password reset sequence.
 * @SIGNON_ERROR_METHOD_OR_MECHANISM_NOT_ALLOWED: Method or mechanism not
 * allowed for this identity.
 * @SIGNON_ERROR_INCORRECT_DATE: Date/time incorrect on device.
 * @SIGNON_ERROR_USER_ERROR: Placeholder to rearrange enumeration - userspace
 * specific.
 *
 * Possible Signon errors.
 */
typedef enum {
    SIGNON_ERROR_UNKNOWN = 1,
    SIGNON_ERROR_INTERNAL_SERVER = 2,
    SIGNON_ERROR_INTERNAL_COMMUNICATION = 3,
    SIGNON_ERROR_PERMISSION_DENIED = 4,

    SIGNON_ERROR_METHOD_NOT_KNOWN = 101,
    SIGNON_ERROR_SERVICE_NOT_AVAILABLE,
    SIGNON_ERROR_INVALID_QUERY,

    SIGNON_ERROR_METHOD_NOT_AVAILABLE = 201,
    SIGNON_ERROR_IDENTITY_NOT_FOUND,
    SIGNON_ERROR_STORE_FAILED,
    SIGNON_ERROR_REMOVE_FAILED,
    SIGNON_ERROR_SIGNOUT_FAILED,
    SIGNON_ERROR_IDENTITY_OPERATION_CANCELED,
    SIGNON_ERROR_CREDENTIALS_NOT_AVAILABLE,
    SIGNON_ERROR_REFERENCE_NOT_FOUND,

    SIGNON_ERROR_MECHANISM_NOT_AVAILABLE = 301,
    SIGNON_ERROR_MISSING_DATA,
    SIGNON_ERROR_INVALID_CREDENTIALS,
    SIGNON_ERROR_NOT_AUTHORIZED,
    SIGNON_ERROR_WRONG_STATE,
    SIGNON_ERROR_OPERATION_NOT_SUPPORTED,
    SIGNON_ERROR_NO_CONNECTION,
    SIGNON_ERROR_NETWORK,
    SIGNON_ERROR_SSL,
    SIGNON_ERROR_RUNTIME,
    SIGNON_ERROR_SESSION_CANCELED,
    SIGNON_ERROR_TIMED_OUT,
    SIGNON_ERROR_USER_INTERACTION,
    SIGNON_ERROR_OPERATION_FAILED,
    SIGNON_ERROR_ENCRYPTION_FAILED,
    SIGNON_ERROR_TOS_NOT_ACCEPTED,
    SIGNON_ERROR_FORGOT_PASSWORD,
    SIGNON_ERROR_METHOD_OR_MECHANISM_NOT_ALLOWED,
    SIGNON_ERROR_INCORRECT_DATE,
    SIGNON_ERROR_USER_ERROR = 400
} SignonError;

GQuark signon_error_quark (void);


#endif
