/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2025 Red Hat, Inc.
 */

#include "nm-default.h"

#include "applet-certificate-agent.h"

#include <gio/gio.h>
#include <gtk/gtk.h>

/*****************************************************************************/

#define CERT_AGENT_OBJECT_PATH "/org/freedesktop/NetworkManager/CertificateAgent"
#define CERT_AGENT_IFACE       "org.freedesktop.NetworkManager.CertificateAgent"
#define NM_DBUS_NAME           "org.freedesktop.NetworkManager"

static const char cert_agent_xml[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<node name=\"/\">"
    "  <interface name=\"org.freedesktop.NetworkManager.CertificateAgent\">"
    "    <method name=\"CertificateVerificationRequest\">"
    "      <arg name=\"ssid\"             type=\"s\" direction=\"in\"/>"
    "      <arg name=\"certificate_name\" type=\"s\" direction=\"in\"/>"
    "      <arg name=\"issuer_name\"      type=\"s\" direction=\"in\"/>"
    "      <arg name=\"organization\"     type=\"s\" direction=\"in\"/>"
    "      <arg name=\"sha256_hex\"       type=\"s\" direction=\"in\"/>"
    "      <arg name=\"expiration_str\"   type=\"s\" direction=\"in\"/>"
    "      <arg name=\"str_disclaimer\"   type=\"s\" direction=\"in\"/>"
    "      <arg name=\"best_url\"         type=\"s\" direction=\"in\"/>"
    "      <arg name=\"response\"         type=\"b\" direction=\"out\"/>"
    "    </method>"
    "    <method name=\"CertificateVerificationFailure\">"
    "      <arg name=\"ssid\"          type=\"s\" direction=\"in\"/>"
    "      <arg name=\"error_message\" type=\"s\" direction=\"in\"/>"
    "    </method>"
    "  </interface>"
    "</node>";

static GDBusConnection *s_conn    = NULL;
static guint            s_reg_id  = 0;
static guint            s_watch   = 0;

/*****************************************************************************/

/* Add one row to a GtkGrid: bold right-aligned label + left-aligned value widget. */
static void
grid_add_row (GtkGrid    *grid,
              int         row,
              const char *label_text,
              GtkWidget  *value_widget)
{
    GtkWidget    *lbl;
    gs_free char *markup = NULL;

    markup = g_strdup_printf ("<b>%s</b>", label_text);
    lbl = gtk_label_new (NULL);
    gtk_label_set_markup (GTK_LABEL (lbl), markup);
    gtk_widget_set_halign (lbl, GTK_ALIGN_END);
    gtk_widget_set_margin_end (lbl, 8);
    gtk_grid_attach (grid, lbl, 0, row, 1, 1);
    gtk_grid_attach (grid, value_widget, 1, row, 1, 1);
}

/* Convenience: plain text value label. */
static GtkWidget *
make_value_label (const char *text)
{
    GtkWidget *lbl = gtk_label_new (text ?: "");
    gtk_widget_set_halign (lbl, GTK_ALIGN_START);
    gtk_label_set_selectable (GTK_LABEL (lbl), TRUE);
    gtk_label_set_line_wrap (GTK_LABEL (lbl), TRUE);
    return lbl;
}

static gboolean
run_cert_dialog (const char *ssid,
                 const char *cn,
                 const char *issuer,
                 const char *org,
                 const char *sha256,
                 const char *exp,
                 const char *disclaimer,
                 const char *url)
{
    GtkWidget *dialog, *content_area;
    GtkWidget *header_lbl;
    GtkWidget *main_grid, *adv_grid, *expander;
    GtkWidget *disc_lbl;
    gs_free char *disc_markup = NULL;
    gint          response;

    dialog = gtk_dialog_new_with_buttons (
        _("Verify Wi-Fi Certificate"),
        NULL,
        GTK_DIALOG_MODAL,
        _("No, Don't Connect"),
        GTK_RESPONSE_CANCEL,
        _("Yes, I trust this certificate. Connect"),
        GTK_RESPONSE_ACCEPT,
        NULL);

    gtk_window_set_default_size (GTK_WINDOW (dialog), 580, -1);
    gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_CANCEL);

    content_area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
    gtk_container_set_border_width (GTK_CONTAINER (content_area), 12);
    gtk_box_set_spacing (GTK_BOX (content_area), 8);

    /* "Is this Network Trusted?" header */
    header_lbl = gtk_label_new (NULL);
    gtk_label_set_markup (GTK_LABEL (header_lbl),
                          _("<b><big>Is this Network Trusted?</big></b>"));
    gtk_widget_set_halign (header_lbl, GTK_ALIGN_START);
    gtk_widget_set_margin_bottom (header_lbl, 4);
    gtk_container_add (GTK_CONTAINER (content_area), header_lbl);

    /* Main info grid: Network Name, Certificate Name, DNS, Disclaimer */
    main_grid = gtk_grid_new ();
    gtk_grid_set_row_spacing (GTK_GRID (main_grid), 4);
    gtk_grid_set_column_spacing (GTK_GRID (main_grid), 4);
    gtk_container_add (GTK_CONTAINER (content_area), main_grid);

    grid_add_row (GTK_GRID (main_grid), 0, _("Network Name:"),     make_value_label (ssid));
    grid_add_row (GTK_GRID (main_grid), 1, _("Certificate Name:"), make_value_label (cn));
    grid_add_row (GTK_GRID (main_grid), 2, _("DNS (URL):"),        make_value_label (url));

    /* Disclaimer in red */
    disc_markup = g_strdup_printf ("<span foreground=\"red\">%s</span>", disclaimer ?: "");
    disc_lbl = gtk_label_new (NULL);
    gtk_label_set_markup (GTK_LABEL (disc_lbl), disc_markup);
    gtk_widget_set_halign (disc_lbl, GTK_ALIGN_START);
    gtk_label_set_line_wrap (GTK_LABEL (disc_lbl), TRUE);
    gtk_label_set_selectable (GTK_LABEL (disc_lbl), TRUE);
    grid_add_row (GTK_GRID (main_grid), 3, _("Disclaimer:"), disc_lbl);

    /* Expander: Advanced Details */
    expander = gtk_expander_new (_("Advanced Details"));
    gtk_widget_set_margin_top (expander, 4);
    gtk_container_add (GTK_CONTAINER (content_area), expander);

    adv_grid = gtk_grid_new ();
    gtk_grid_set_row_spacing (GTK_GRID (adv_grid), 4);
    gtk_grid_set_column_spacing (GTK_GRID (adv_grid), 4);
    gtk_widget_set_margin_top (adv_grid, 6);
    gtk_container_add (GTK_CONTAINER (expander), adv_grid);

    grid_add_row (GTK_GRID (adv_grid), 0, _("Issuer:"),             make_value_label (issuer));
    grid_add_row (GTK_GRID (adv_grid), 1, _("Organization:"),       make_value_label (org));
    grid_add_row (GTK_GRID (adv_grid), 2, _("Expires On:"),         make_value_label (exp));
    grid_add_row (GTK_GRID (adv_grid), 3, _("SHA-256 Fingerprint:"), make_value_label (sha256));

    gtk_widget_show_all (dialog);

    response = gtk_dialog_run (GTK_DIALOG (dialog));
    gtk_widget_destroy (dialog);

    return (response == GTK_RESPONSE_ACCEPT);
}

/*****************************************************************************/

static void
handle_method_call (GDBusConnection       *conn,
                    const gchar           *sender,
                    const gchar           *object_path,
                    const gchar           *iface,
                    const gchar           *method_name,
                    GVariant              *params,
                    GDBusMethodInvocation *invocation,
                    gpointer               user_data)
{
    if (g_strcmp0 (method_name, "CertificateVerificationRequest") == 0) {
        const char *ssid, *cn, *issuer, *org, *sha256, *exp, *disclaimer, *url;
        gboolean    accepted;

        g_variant_get (params,
                       "(&s&s&s&s&s&s&s&s)",
                       &ssid,
                       &cn,
                       &issuer,
                       &org,
                       &sha256,
                       &exp,
                       &disclaimer,
                       &url);

        accepted = run_cert_dialog (ssid, cn, issuer, org, sha256, exp, disclaimer, url);
        g_dbus_method_invocation_return_value (invocation, g_variant_new ("(b)", accepted));

    } else if (g_strcmp0 (method_name, "CertificateVerificationFailure") == 0) {
        const char *ssid, *msg;
        GtkWidget  *err_dialog;

        g_variant_get (params, "(&s&s)", &ssid, &msg);

        err_dialog = gtk_message_dialog_new (
            NULL,
            GTK_DIALOG_MODAL,
            GTK_MESSAGE_ERROR,
            GTK_BUTTONS_OK,
            _("Certificate verification failed for \"%s\":\n%s"),
            ssid ?: "",
            msg  ?: "");
        gtk_window_set_title (GTK_WINDOW (err_dialog), _("Certificate Error"));
        gtk_dialog_run (GTK_DIALOG (err_dialog));
        gtk_widget_destroy (err_dialog);

        g_dbus_method_invocation_return_value (invocation, NULL);

    } else {
        g_dbus_method_invocation_return_error (invocation,
                                               G_DBUS_ERROR,
                                               G_DBUS_ERROR_UNKNOWN_METHOD,
                                               "Unknown method: %s",
                                               method_name);
    }
}

static const GDBusInterfaceVTable cert_agent_vtable = {
    .method_call = handle_method_call,
};

/*****************************************************************************/

/* Register with NM daemon via the same AgentManager.RegisterWithCapabilities
 * every other secret agent uses (see applet-agent.c) — object is already on
 * bus, just tell NM about it. NM_SECRET_AGENT_CAPABILITY_WIFI_TOFU is what
 * lets NM's nm_agent_manager_find_secret_agent() find this process for a
 * TOFU popup, filtered by that capability plus the real ACL/UID checks
 * GetSecrets already applies — no separate registration entry point needed. */
static void
nm_register_cert_agent (void)
{
    GError   *error = NULL;
    GVariant *reply;

    reply = g_dbus_connection_call_sync (s_conn,
                                          NM_DBUS_NAME,
                                          "/org/freedesktop/NetworkManager/AgentManager",
                                          "org.freedesktop.NetworkManager.AgentManager",
                                          "RegisterWithCapabilities",
                                          g_variant_new ("(su)",
                                                         "nm-applet-tofu",
                                                         (guint32) NM_SECRET_AGENT_CAPABILITY_WIFI_TOFU),
                                          NULL,
                                          G_DBUS_CALL_FLAGS_NONE,
                                          5000,
                                          NULL,
                                          &error);
    if (!reply) {
        g_warning ("CertificateAgent: RegisterWithCapabilities failed: %s", error->message);
        g_error_free (error);
        return;
    }
    g_variant_unref (reply);
}

/* Called whenever org.freedesktop.NetworkManager appears on the bus (including after restart). */
static void
on_nm_appeared (GDBusConnection *conn,
                const char      *name,
                const char      *name_owner,
                gpointer         user_data)
{
    nm_register_cert_agent ();
}

gboolean
applet_certificate_agent_register (void)
{
    GDBusNodeInfo      *node_info;
    GDBusInterfaceInfo *iface_info;
    GError             *error = NULL;

    s_conn = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
    if (!s_conn) {
        g_warning ("CertificateAgent: cannot get system bus: %s", error->message);
        g_error_free (error);
        return FALSE;
    }

    node_info = g_dbus_node_info_new_for_xml (cert_agent_xml, &error);
    if (!node_info) {
        g_warning ("CertificateAgent: bad introspection XML: %s", error->message);
        g_error_free (error);
        g_clear_object (&s_conn);
        return FALSE;
    }

    iface_info = g_dbus_node_info_lookup_interface (node_info, CERT_AGENT_IFACE);

    s_reg_id = g_dbus_connection_register_object (s_conn,
                                                   CERT_AGENT_OBJECT_PATH,
                                                   iface_info,
                                                   &cert_agent_vtable,
                                                   NULL,
                                                   NULL,
                                                   &error);
    g_dbus_node_info_unref (node_info);

    if (!s_reg_id) {
        g_warning ("CertificateAgent: register object failed: %s", error->message);
        g_error_free (error);
        g_clear_object (&s_conn);
        return FALSE;
    }

    /* Watch for NM: fires immediately if NM already running, and again on any restart. */
    s_watch = g_bus_watch_name_on_connection (s_conn,
                                               NM_DBUS_NAME,
                                               G_BUS_NAME_WATCHER_FLAGS_NONE,
                                               on_nm_appeared,
                                               NULL,
                                               NULL,
                                               NULL);
    return TRUE;
}

void
applet_certificate_agent_unregister (void)
{
    if (!s_conn)
        return;

    if (s_watch) {
        g_bus_unwatch_name (s_watch);
        s_watch = 0;
    }

    g_dbus_connection_call_sync (s_conn,
                                  NM_DBUS_NAME,
                                  "/org/freedesktop/NetworkManager/AgentManager",
                                  "org.freedesktop.NetworkManager.AgentManager",
                                  "Unregister",
                                  NULL,
                                  NULL,
                                  G_DBUS_CALL_FLAGS_NONE,
                                  2000,
                                  NULL,
                                  NULL);

    if (s_reg_id) {
        g_dbus_connection_unregister_object (s_conn, s_reg_id);
        s_reg_id = 0;
    }

    g_clear_object (&s_conn);
}
