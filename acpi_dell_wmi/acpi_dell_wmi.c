/*-
 * Copyright (c) 2016 Wilfried Meindl <wilfried.meindl@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include "opt_acpi.h"
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/kernel.h>
// #include <sys/types.h>
#include <sys/bus.h>
#include <sys/sbuf.h>
#include <sys/module.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>
#include <dev/acpica/acpivar.h>
#include "acpi_wmi_if.h"

#define _COMPONENT ACPI_OEM
ACPI_MODULE_NAME("DELL-WMI")

#define ACPI_DELL_WMI_MGMT_GUID		"8D9DDCBC-A997-11DA-B012-B622A1EF5492"
#define ACPI_DELL_WMI_EVENT_GUID	"9DBB5994-A997-11DA-B012-B622A1EF5492"



struct acpi_dell_wmi_softc {
	device_t	dev;
	device_t	wmi_dev;
	const char	*notify_guid;
};

static void	acpi_dell_wmi_identify(driver_t *driver, device_t parent);
static int	acpi_dell_wmi_probe(device_t dev);
static int	acpi_dell_wmi_attach(device_t dev);
static int	acpi_dell_wmi_detach(device_t dev);
static void	acpi_dell_wmi_notify(ACPI_HANDLE h, UINT32 notify, void *context);
static __inline void acpi_dell_wmi_free_buffer(ACPI_BUFFER *buf);

static device_method_t acpi_dell_wmi_methods[] = {
	DEVMETHOD(device_identify, acpi_dell_wmi_identify),
	DEVMETHOD(device_probe, acpi_dell_wmi_probe),
	DEVMETHOD(device_attach, acpi_dell_wmi_attach),
	DEVMETHOD(device_detach, acpi_dell_wmi_detach),

	DEVMETHOD_END
};

static driver_t acpi_dell_wmi_driver = {
	"acpi_dell_wmi",
	acpi_dell_wmi_methods,
	sizeof(struct acpi_dell_wmi_softc),
};

static devclass_t acpi_dell_wmi_devclass;

DRIVER_MODULE(acpi_dell_wmi, acpi_wmi, acpi_dell_wmi_driver,
    acpi_dell_wmi_devclass, 0, 0);
MODULE_DEPEND(acpi_dell_wmi, acpi_wmi, 1, 1, 1);
MODULE_DEPEND(acpi_dell_wmi, acpi, 1, 1, 1);

static void
acpi_dell_wmi_identify(driver_t *driver, device_t parent)
{
	/* Don't do anything if driver is disabled. */
	if (acpi_disabled("dell_wmi"))
		return;

	/* Don't do anything if device exists already. */
	if (device_find_child(parent, "acpi_dell_wmi", -1) != NULL)
		return;

	/* Check WMI management GUID. */
	if (!ACPI_WMI_PROVIDES_GUID_STRING(parent,
	    ACPI_DELL_WMI_MGMT_GUID))
		return;

	if (BUS_ADD_CHILD(parent, 0, "acpi_dell_wmi", -1) == NULL)
		device_printf(parent, "add acpi_dell_wmi child failed\n");
}

static int
acpi_dell_wmi_probe(device_t dev)
{
	if (!ACPI_WMI_PROVIDES_GUID_STRING(device_get_parent(dev),
	    ACPI_DELL_WMI_MGMT_GUID))
		return (EINVAL);
	device_set_desc(dev, "DELL WMI device");
	return (0);
}

static int
acpi_dell_wmi_attach(device_t dev)
{
	struct acpi_dell_wmi_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;
	sc->wmi_dev = device_get_parent(dev);

	/* Check management GUID. */
	if (!ACPI_WMI_PROVIDES_GUID_STRING(sc->wmi_dev,
	    ACPI_DELL_WMI_MGMT_GUID)) {
		device_printf(dev,
		    "WMI device does not provide the DELL management GUID\n");
		return (EINVAL);
	}

	/* Install WMI event handler. */
	if (ACPI_WMI_INSTALL_EVENT_HANDLER(sc->wmi_dev,
	    ACPI_DELL_WMI_EVENT_GUID, acpi_dell_wmi_notify, dev)) {
		sc->notify_guid = NULL;
	      	device_printf(dev, "Could not install event handler!\n");
	} else {
	      	sc->notify_guid = ACPI_DELL_WMI_EVENT_GUID;
	}

	return (0);
}

static int
acpi_dell_wmi_detach(device_t dev)
{
	struct acpi_dell_wmi_softc *sc = device_get_softc(dev);

	if (sc->notify_guid)
		ACPI_WMI_REMOVE_EVENT_HANDLER(dev, sc->notify_guid);

	return (0);
}

static void
acpi_dell_wmi_user_notify(char *type, char *str)
{
    	char buf[16];

	snprintf(buf, sizeof(buf), "notify=%s", str);
	devctl_notify("ACPI", "DELL", type, buf);
}

static void
acpi_dell_wmi_notify(ACPI_HANDLE h, UINT32 notify, void *context)
{
	device_t dev = context;
	ACPI_BUFFER response;
	ACPI_OBJECT *obj;
	ACPI_SIZE size;
	UINT16 *data, *data_end;
	UINT16 length;
	int i;

	struct acpi_dell_wmi_softc *sc = device_get_softc(dev);
	response = (ACPI_BUFFER){ ACPI_ALLOCATE_BUFFER, NULL };
	ACPI_WMI_GET_EVENT_DATA(sc->wmi_dev, notify, &response);
	obj = (ACPI_OBJECT *) response.Pointer;

	if (!obj) {
		device_printf(dev, "no data available for WMI event\n");
		goto cleanup;
	}

	if (! (obj->Type == ACPI_TYPE_BUFFER)) {
		device_printf(dev, "wrong type of WMI event data\n");
		goto cleanup;
	}

	data = (UINT16 *) obj->Buffer.Pointer;
	size = obj->Buffer.Length / 2;
	data_end = data + size;

	while (data < data_end) {
		length = data[0];

		if (data + length > data_end) {
			device_printf(dev, "wrong length of WMI event data");
			goto cleanup;
		}

		if (length == 0)
			break;

		switch (data[1]) {
		case 0x0010:	/* Keys */
			for (i = 2; i <= length; i++)
				switch (data[i]) {
				case 0x0048:	/* Display Brightness up */
					acpi_dell_wmi_user_notify("KEY", "DSPBRUP");
					break;
				case 0x0050:	/* Display brightness down */
					acpi_dell_wmi_user_notify("KEY", "DSPBRDN");
					break;
				case 0x004d:	/* Cycle keyboard backlight brightness */
					acpi_dell_wmi_user_notify("KEY", "KBBLCYC");
					break;
				case 0x0010:	/* Fn + Q */
					acpi_dell_wmi_user_notify("KEY", "FNQ");
					break;
				case 0x0011:	/* Fn + W */
					acpi_dell_wmi_user_notify("KEY", "FNW");
					break;
				case 0x0012:	/* Fn + E */
					acpi_dell_wmi_user_notify("KEY", "FNE");
					break;
				case 0x0013:	/* Fn + R */
					acpi_dell_wmi_user_notify("KEY", "FNR");
					break;
				case 0x0014:	/* Fn + T */
					acpi_dell_wmi_user_notify("KEY", "FNT");
					break;
				case 0x001E:	/* Fn + A */
					acpi_dell_wmi_user_notify("KEY", "FNA");
					break;
				case 0x001F:	/* Fn + S */
					acpi_dell_wmi_user_notify("KEY", "FNS");
					break;
				case 0x0020:	/* Fn + D */
					acpi_dell_wmi_user_notify("KEY", "FND");
					break;
				case 0x0021:	/* Fn + F */
					acpi_dell_wmi_user_notify("KEY", "FNF");
					break;
				case 0x0022:	/* Fn + G */
					acpi_dell_wmi_user_notify("KEY", "FNG");
					break;
				default:
					device_printf(dev,
						      "Unknown key 0x%04x",
						      (int)data[i]);
				}
			break;
		case 0x0011:	/* Events */
			for (i = 2; i <= length; i++)
				switch (data[i]) {
				case 0x01E1:	/* KBD backlight off */
					acpi_dell_wmi_user_notify("EVENT",
								  "KBBLOFF");
					break;
				case 0x02EA:	/* KBD backlight level 1 */
					acpi_dell_wmi_user_notify("EVENT",
								  "KBBLLV1");
					break;
				case 0x02EB:	/* KBD backlight level 2 */
					acpi_dell_wmi_user_notify("EVENT",
								  "KBBLLV2");
					break;
				case 0x02EC:	/* KBD backlight level 3 */
					acpi_dell_wmi_user_notify("EVENT",
								  "KBBLLV3");
					break;
				case 0x02F6:	/* KBD backlight level 4 */
					acpi_dell_wmi_user_notify("EVENT",
								  "KBBLLV4");
					break;
				default:
					device_printf(dev,
						      "Unknown event 0x%04x",
						      (int)data[i]);
				}
			break;
		default:
			device_printf(dev,
				      "Unknown type of WMI event: 0x%04x\n",
				      (int)data[1]);
		}

		data += length + 1;
	}

cleanup:
	acpi_dell_wmi_free_buffer(&response);
}


static __inline void
acpi_dell_wmi_free_buffer(ACPI_BUFFER* buf) {
	if (buf && buf->Pointer) {
		AcpiOsFree(buf->Pointer);
	}
}
