#include "opt_acpi.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>

#include <contrib/dev/acpica/include/acpi.h>

#include <dev/acpica/acpivar.h>

struct acpi_iichid_softc {
};

static char *acpi_iichid_ids[] = {
	"PNP0C50",
	"ACPI0C50",
	NULL,
};

static int
acpi_iichid_probe(device_t dev)
{
	int rv;

	if (acpi_disabled("iichid"))
		return (ENXIO);
	rv = ACPI_ID_PROBE(device_get_parent(dev), dev, acpi_iichid_ids, NULL);
	if (rv <= 0)
		device_set_desc(dev, "HID over I2C device");
	printf("rv is %d\n", rv);

	return (rv);
}

static int
acpi_iichid_attach(device_t dev)
{

	return (ENXIO);
}

static int
acpi_iichid_detach(device_t dev)
{

	return (0);
}

static device_method_t acpi_iichid_methods[] = {
	DEVMETHOD(device_probe, acpi_iichid_probe),
	DEVMETHOD(device_attach, acpi_iichid_attach),
	DEVMETHOD(device_detach, acpi_iichid_detach),
};

static driver_t acpi_iichid_driver = {
	"acpi_iichid",
	acpi_iichid_methods,
	sizeof(struct acpi_iichid_softc),
};

static devclass_t acpi_iichid_devclass;
DRIVER_MODULE(acpi_iichid, iicbus, acpi_iichid_driver, acpi_iichid_devclass,
    NULL, 0);
