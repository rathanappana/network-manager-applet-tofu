// SPDX-License-Identifier: GPL-2.0+

#ifndef __APPLET_CERTIFICATE_AGENT_H__
#define __APPLET_CERTIFICATE_AGENT_H__

#include <NetworkManager.h>

typedef struct _AppletCertificateAgent AppletCertificateAgent;

AppletCertificateAgent *applet_certificate_agent_new (NMClient *client,
                                                      GDBusConnection *connection);
void applet_certificate_agent_free (AppletCertificateAgent *self);

#endif /* __APPLET_CERTIFICATE_AGENT_H__ */
