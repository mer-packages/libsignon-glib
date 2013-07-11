#!/bin/sh

# Environment variables for the signon daemon
export SSO_LOGGING_LEVEL=2
export SSO_STORAGE_PATH="/tmp"
export SSO_DAEMON_TIMEOUT=5
export SSO_IDENTITY_TIMEOUT=5
export SSO_AUTHSESSION_TIMEOUT=5
export SSO_EXTENSIONS_DIR="/tmp" # this disables all extensions

#Environment variables for the test application
export G_MESSAGES_DEBUG=all

TEST_APP=./signon-glib-testsuite

# If dbus-test-runner exists, use it to run the tests in a separate D-Bus
# session
if command -v dbus-test-runner > /dev/null ; then
    echo "Using dbus-test-runner"
    dbus-test-runner -m 180 -t signond \
        -t "$TEST_APP" -f com.google.code.AccountsSSO.SingleSignOn
else
    echo "Using existing D-Bus session"
    pkill signond || true
    trap "pkill -9 signond" EXIT
    signond &
    sleep 2

    $TEST_APP
fi
