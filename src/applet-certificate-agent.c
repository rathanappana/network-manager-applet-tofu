// SPDX-License-Identifier: GPL-2.0+

/* Lets the user trust the certificate of an 802.1X authentication server on
 * first use. NetworkManager asks through the
 * org.freedesktop.NetworkManager.CertificateAgent D-Bus interface, which is
 * exported on the connection of the secret agent of the applet. */

#include "nm-default.h"

#include "applet-certificate-agent.h"

#ifdef NM_SETTING_802_1X_TRUST_ON_FIRST_USE

static const char introspection_xml[] =
    "<node>"
    "  <interface name='" NM_DBUS_INTERFACE_CERTIFICATE_AGENT "'>"
    "    <method name='ConfirmServerCertificate'>"
    "      <arg name='connection_path' type='o' direction='in'/>"
    "      <arg name='certificate' type='a{sv}' direction='in'/>"
    "      <arg name='trusted' type='b' direction='out'/>"
    "    </method>"
    "    <method name='CancelConfirmServerCertificate'>"
    "      <arg name='connection_path' type='o' direction='in'/>"
    "    </method>"
    "  </interface>"
    "</node>";

struct _AppletCertificateAgent {
	NMClient *client;
	GDBusConnection *connection;
	guint registration_id;
	GHashTable *requests; /* connection path -> Request */
};

typedef struct {
	char *connection_path;
	GDBusMethodInvocation *invocation;
	GtkWidget *dialog;
} Request;

static void request_free (Request *request) {
	if (request->invocation) {
		g_dbus_method_invocation_return_error_literal (
		    request->invocation, G_IO_ERROR, G_IO_ERROR_CANCELLED, "The request was cancelled");
	}
	gtk_widget_destroy (request->dialog);
	g_free (request->connection_path);
	g_free (request);
}

/*****************************************************************************/

/* The certificate comes from the network. Its text must not add lines. */
static char *printable (const char *text) {
	char *dup = g_strdup (text);
	char *p;

	for (p = dup; p && *p; p++) {
		if (g_ascii_iscntrl (*p))
			*p = ' ';
	}
	return dup;
}

/* Returns the value of @attribute in an RFC 4514 distinguished name, like
 * "CN=radius.example.com,O=Example". */
static char *dn_get (const char *dn, const char *attribute) {
	gsize len = strlen (attribute);
	const char *p = dn;

	while (p && *p) {
		const char *end = p;
		GString *value;

		while (*end && *end != ',') {
			if (*end == '\\' && end[1])
				end++;
			end++;
		}
		if (g_ascii_strncasecmp (p, attribute, len) == 0 && p[len] == '=') {
			value = g_string_new (NULL);
			for (p += len + 1; p < end; p++) {
				if (*p == '\\' && p + 1 < end)
					p++;
				g_string_append_c (value, *p);
			}
			return g_string_free (value, FALSE);
		}
		p = *end ? end + 1 : end;
	}
	return NULL;
}

typedef struct {
	char *subject;
	char *issuer;
	char *expires;
} CertDetails;

static void cert_details_clear (CertDetails *details) {
	g_free (details->subject);
	g_free (details->issuer);
	g_free (details->expires);
}

static void cert_details_read (CertDetails *details, GVariant *der) {
#if GLIB_CHECK_VERSION(2, 70, 0)
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS
	gs_unref_object GTlsCertificate *certificate = NULL;
	gs_free char *base64 = NULL;
	gs_free char *pem = NULL;
	GDateTime *expires;
	const guint8 *data;
	gsize len;

	data = g_variant_get_fixed_array (der, &len, 1);
	base64 = g_base64_encode (data, len);
	pem = g_strdup_printf ("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", base64);
	certificate = g_tls_certificate_new_from_pem (pem, -1, NULL);
	if (!certificate)
		return;

	details->subject = g_tls_certificate_get_subject_name (certificate);
	details->issuer = g_tls_certificate_get_issuer_name (certificate);
	expires = g_tls_certificate_get_not_valid_after (certificate);
	if (expires) {
		details->expires = g_date_time_format (expires, "%x");
		g_date_time_unref (expires);
	}
	G_GNUC_END_IGNORE_DEPRECATIONS
#endif
}

static char *get_dns_names (GVariant *certificate) {
	gs_free const char **altsubject = NULL;
	GString *names = g_string_new (NULL);
	guint i;

	if (g_variant_lookup (certificate, "altsubject", "^a&s", &altsubject)) {
		for (i = 0; altsubject[i]; i++) {
			if (g_str_has_prefix (altsubject[i], "DNS:")) {
				if (names->len)
					g_string_append (names, ", ");
				g_string_append (names, &altsubject[i][NM_STRLEN ("DNS:")]);
			}
		}
	}
	return g_string_free (names, FALSE);
}

/*****************************************************************************/

static GtkWidget *add_label (GtkWidget *box, const char *markup) {
	GtkWidget *label = gtk_label_new (NULL);

	gtk_label_set_markup (GTK_LABEL (label), markup);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (label), 70);
	gtk_widget_set_halign (label, GTK_ALIGN_START);
	gtk_container_add (GTK_CONTAINER (box), label);
	return label;
}

/* Adds a row with a bold name and a selectable value. */
static void add_row (GtkGrid *grid, int *row, const char *name, const char *value) {
	gs_free char *markup = NULL;
	gs_free char *text = NULL;
	GtkWidget *label;

	if (!value || !value[0])
		return;

	markup = g_markup_printf_escaped ("<b>%s</b>", name);
	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), markup);
	gtk_widget_set_halign (label, GTK_ALIGN_END);
	gtk_widget_set_valign (label, GTK_ALIGN_START);
	gtk_grid_attach (grid, label, 0, *row, 1, 1);

	text = printable (value);
	label = gtk_label_new (text);
	gtk_widget_set_halign (label, GTK_ALIGN_START);
	gtk_label_set_selectable (GTK_LABEL (label), TRUE);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	gtk_label_set_line_wrap_mode (GTK_LABEL (label), PANGO_WRAP_WORD_CHAR);
	gtk_label_set_max_width_chars (GTK_LABEL (label), 50);
	gtk_grid_attach (grid, label, 1, *row, 1, 1);

	(*row)++;
}

static GtkWidget *new_grid (void) {
	GtkWidget *grid = gtk_grid_new ();

	gtk_grid_set_row_spacing (GTK_GRID (grid), 4);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 8);
	return grid;
}

static GtkWidget *create_dialog (AppletCertificateAgent *self, const char *connection_path,
                                 GVariant *certificate) {
	CertDetails details = {};
	gs_unref_variant GVariant *der = NULL;
	gs_unref_variant GVariant *ssid = NULL;
	gs_free char *ssid_str = NULL;
	gs_free char *dns_names = NULL;
	gs_free char *name = NULL;
	gs_free char *organization = NULL;
	gs_free char *issuer = NULL;
	gs_free char *markup = NULL;
	const char *fingerprint = NULL;
	const char *subject = NULL;
	const char *anchor = NULL;
	gboolean changed = FALSE;
	gboolean system_trusted = FALSE;
	gboolean has_system_trusted;
	NMRemoteConnection *connection;
	GtkWidget *dialog, *box, *grid, *expander;
	int row = 0;

	connection = nm_client_get_connection_by_path (self->client, connection_path);
	ssid = g_variant_lookup_value (certificate, "ssid", G_VARIANT_TYPE_BYTESTRING);
	if (ssid) {
		gsize len;
		const guint8 *data = g_variant_get_fixed_array (ssid, &len, 1);

		ssid_str = nm_utils_ssid_to_utf8 (data, len);
	}
	der = g_variant_lookup_value (certificate, "certificate", G_VARIANT_TYPE_BYTESTRING);
	if (der)
		cert_details_read (&details, der);
	g_variant_lookup (certificate, "fingerprint", "&s", &fingerprint);
	g_variant_lookup (certificate, "subject", "&s", &subject);
	g_variant_lookup (certificate, "trust-anchor", "&s", &anchor);
	g_variant_lookup (certificate, "changed", "b", &changed);
	has_system_trusted = g_variant_lookup (certificate, "system-trusted", "b", &system_trusted);
	dns_names = get_dns_names (certificate);
	if (details.subject) {
		name = dn_get (details.subject, "CN");
		organization = dn_get (details.subject, "O");
	}
	if (details.issuer)
		issuer = dn_get (details.issuer, "CN");

	dialog = gtk_dialog_new_with_buttons (
	    changed ? _("Wi-Fi Certificate Changed") : _("Verify Wi-Fi Certificate"), NULL, 0,
	    /* NetworkManager deletes a connection that was never trusted, if the
	     * user rejects its server. */
	    changed ? _("No, Don’t Connect") : _("No, Don’t Connect and Forget Network"),
	    GTK_RESPONSE_REJECT, _("Yes, I Trust This Certificate. Connect"), GTK_RESPONSE_ACCEPT,
	    NULL);
	gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_REJECT);
	gtk_window_set_icon_name (GTK_WINDOW (dialog), "dialog-password");

	box = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
	gtk_container_set_border_width (GTK_CONTAINER (box), 12);
	gtk_box_set_spacing (GTK_BOX (box), 8);

	markup = g_markup_printf_escaped ("<b><big>%s</big></b>",
	                                  changed ? _("The certificate of this network changed")
	                                          : _("Is this network trusted?"));
	add_label (box, markup);
	nm_clear_g_free (&markup);

	if (changed) {
		add_label (box, _("The authentication server presented a different certificate than the "
		                   "one you trusted before. Servers renew their certificates, but this may "
		                   "also be an attacker impersonating the network."));
	} else
		add_label (
		    box,
		    _("The authentication server presented a certificate that cannot be verified yet."));
	add_label (box, _("Only trust it if its fingerprint matches the one published by your network "
	                   "administrator."));

	grid = new_grid ();
	gtk_container_add (GTK_CONTAINER (box), grid);
	add_row (GTK_GRID (grid), &row, _("Connection:"),
	         connection ? nm_connection_get_id (NM_CONNECTION (connection)) : NULL);
	add_row (GTK_GRID (grid), &row, _("Network name:"), ssid_str);
	add_row (GTK_GRID (grid), &row, _("Server:"), dns_names);
	add_row (GTK_GRID (grid), &row, _("Certificate name:"), name);

	/* Older versions of NetworkManager don't tell. */
	if (!has_system_trusted) {
		/* nothing */
	} else if (system_trusted) {
		add_label (box,
		           _("The certificate is issued by a CA that this computer trusts. This supports, "
		              "but does not prove, that the server is genuine."));
	} else {
		markup = g_markup_printf_escaped ("<span foreground=\"red\">%s</span>",
		                                  _("The certificate is not issued by a CA that this "
		                                     "computer trusts."));
		add_label (box, markup);
		nm_clear_g_free (&markup);
	}

	if (nm_streq0 (anchor, "server-certificate")) {
		add_label (box,
		           _("If you trust it, only this certificate will be accepted. You will be asked "
		              "again when the server changes it."));
	} else if (anchor) {
		add_label (box,
		           _("If you trust it, certificates for this server name from the same CA will be "
		              "accepted, so that the server can renew its certificate."));
	}

	expander = gtk_expander_new (_("Advanced Details"));
	gtk_container_add (GTK_CONTAINER (box), expander);
	grid = new_grid ();
	gtk_widget_set_margin_top (grid, 6);
	gtk_container_add (GTK_CONTAINER (expander), grid);
	row = 0;
	add_row (GTK_GRID (grid), &row, _("Subject:"), details.subject ?: subject);
	add_row (GTK_GRID (grid), &row, _("Organization:"), organization);
	add_row (GTK_GRID (grid), &row, _("Issuer:"), issuer ?: details.issuer);
	add_row (GTK_GRID (grid), &row, _("Expires on:"), details.expires);
	add_row (GTK_GRID (grid), &row, _("SHA-256 fingerprint:"), fingerprint);

	gtk_widget_show_all (dialog);
	cert_details_clear (&details);
	return dialog;
}

/*****************************************************************************/

static void dialog_response_cb (GtkDialog *dialog, int response, gpointer user_data) {
	AppletCertificateAgent *self = user_data;
	const char *connection_path = g_object_get_data (G_OBJECT (dialog), "connection-path");
	Request *request = g_hash_table_lookup (self->requests, connection_path);

	/* Closing the dialog is no answer: NetworkManager keeps the connection. */
	if (response == GTK_RESPONSE_ACCEPT || response == GTK_RESPONSE_REJECT) {
		g_dbus_method_invocation_return_value (g_steal_pointer (&request->invocation),
		                                       g_variant_new ("(b)", response == GTK_RESPONSE_ACCEPT));
	} else {
		g_dbus_method_invocation_return_error_literal (g_steal_pointer (&request->invocation),
		                                               NM_SECRET_AGENT_ERROR,
		                                               NM_SECRET_AGENT_ERROR_USER_CANCELED,
		                                               "Dismissed by the user");
	}
	g_hash_table_remove (self->requests, connection_path);
}

static void method_call (GDBusConnection *connection, const char *sender, const char *object_path,
                         const char *interface_name, const char *method_name, GVariant *parameters,
                         GDBusMethodInvocation *invocation, gpointer user_data) {
	AppletCertificateAgent *self = user_data;
	gs_unref_variant GVariant *certificate = NULL;
	const char *connection_path;
	Request *request;

	if (!nm_streq0 (sender,
	                NM_LIBNM_COMPAT_UNDEPRECATE (nm_client_get_dbus_name_owner (self->client)))) {
		g_dbus_method_invocation_return_error_literal (invocation, G_DBUS_ERROR,
		                                               G_DBUS_ERROR_ACCESS_DENIED,
		                                               "Only NetworkManager may call this method");
		return;
	}

	if (nm_streq (method_name, "CancelConfirmServerCertificate")) {
		g_variant_get (parameters, "(&o)", &connection_path);
		g_hash_table_remove (self->requests, connection_path);
		g_dbus_method_invocation_return_value (invocation, NULL);
		return;
	}

	g_variant_get (parameters, "(&o@a{sv})", &connection_path, &certificate);
	if (g_hash_table_contains (self->requests, connection_path)) {
		g_dbus_method_invocation_return_error_literal (
		    invocation, G_DBUS_ERROR, G_DBUS_ERROR_LIMITS_EXCEEDED,
		    "The certificate is already being confirmed");
		return;
	}

	request = g_new0 (Request, 1);
	request->connection_path = g_strdup (connection_path);
	request->invocation = invocation;
	request->dialog = create_dialog (self, connection_path, certificate);
	g_object_set_data_full (G_OBJECT (request->dialog), "connection-path",
	                        g_strdup (connection_path), g_free);
	g_signal_connect (request->dialog, "response", G_CALLBACK (dialog_response_cb), self);
	g_hash_table_insert (self->requests, request->connection_path, request);
	gtk_window_present (GTK_WINDOW (request->dialog));
}

/**
 * applet_certificate_agent_new:
 * @client: the #NMClient, to verify that requests come from NetworkManager
 * @connection: the D-Bus connection of the secret agent, which must have
 *   registered with %NM_SECRET_AGENT_CAPABILITY_TRUST_ON_FIRST_USE
 *
 * Returns: the agent, or %NULL if it could not be exported.
 */
AppletCertificateAgent *applet_certificate_agent_new (NMClient *client,
                                                      GDBusConnection *connection) {
	static const GDBusInterfaceVTable vtable = {.method_call = method_call};
	gs_free_error GError *error = NULL;
	AppletCertificateAgent *self;
	GDBusNodeInfo *node_info;

	self = g_new0 (AppletCertificateAgent, 1);
	self->client = g_object_ref (client);
	self->connection = g_object_ref (connection);
	self->requests =
	    g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify)request_free);

	node_info = g_dbus_node_info_new_for_xml (introspection_xml, NULL);
	self->registration_id =
	    g_dbus_connection_register_object (connection, NM_DBUS_PATH_CERTIFICATE_AGENT,
	                                       node_info->interfaces[0], &vtable, self, NULL, &error);
	g_dbus_node_info_unref (node_info);

	if (!self->registration_id) {
		g_warning ("Could not export the certificate agent: %s", error->message);
		applet_certificate_agent_free (self);
		return NULL;
	}
	return self;
}

void applet_certificate_agent_free (AppletCertificateAgent *self) {
	if (!self)
		return;

	if (self->registration_id)
		g_dbus_connection_unregister_object (self->connection, self->registration_id);
	g_hash_table_unref (self->requests);
	g_object_unref (self->connection);
	g_object_unref (self->client);
	g_free (self);
}

#else /* NM_SETTING_802_1X_TRUST_ON_FIRST_USE */

AppletCertificateAgent *applet_certificate_agent_new (NMClient *client,
                                                      GDBusConnection *connection) {
	return NULL;
}

void applet_certificate_agent_free (AppletCertificateAgent *self) {}

#endif /* NM_SETTING_802_1X_TRUST_ON_FIRST_USE */
