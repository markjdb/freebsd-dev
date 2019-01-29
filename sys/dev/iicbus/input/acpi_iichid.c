#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/rman.h>

#include <sys/malloc.h>

#include <dev/iicbus/input/iichid.h>
#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iiconf.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>

#include <dev/acpica/acpivar.h>

static device_probe_t		acpi_iichid_probe;
static device_attach_t		acpi_iichid_attach;
static device_detach_t		acpi_iichid_detach;

static devclass_t acpi_iichid_devclass;

static device_method_t acpi_iichid_methods[] = {
	/* device interface */
	DEVMETHOD(device_probe, acpi_iichid_probe),
	DEVMETHOD(device_attach, acpi_iichid_attach),
	DEVMETHOD(device_detach, acpi_iichid_detach),

	DEVMETHOD_END
};

static driver_t acpi_iichid_driver = {
	.name = "acpi_iichid",
	.methods = acpi_iichid_methods,
	.size = sizeof(struct acpi_iichid_softc),
};

static char *acpi_iichid_ids[] = {
	"PNP0C50",
	"ACPI0C50",
	NULL
};

static ACPI_STATUS
acpi_iichid_walk_handler(ACPI_RESOURCE *res, void *context)
{
	struct acpi_iichid_softc *sc;

	sc = context;

	switch(res->Type) {
		case ACPI_RESOURCE_TYPE_SERIAL_BUS:
			//device_printf(sc->dev, " - serial bus: ");
			if (res->Data.CommonSerialBus.Type != ACPI_RESOURCE_SERIAL_TYPE_I2C) {
				device_printf(sc->dev, "wrong bus type, should be %d is %d\n", ACPI_RESOURCE_SERIAL_TYPE_I2C, res->Data.CommonSerialBus.Type);
				return (AE_TYPE);
			} else {
				//device_printf(sc->dev, "0x%x on %s\n", le16toh(res->Data.I2cSerialBus.SlaveAddress), res->Data.CommonSerialBus.ResourceSource.StringPtr);
				sc->hw.device_addr = res->Data.I2cSerialBus.SlaveAddress;
			}
			break;
		case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
			if (res->Data.ExtendedIrq.InterruptCount > 0) {
				device_printf(sc->dev, " - irq: %d\n", (int)res->Data.ExtendedIrq.Interrupts[0]);
				sc->irq = res->Data.ExtendedIrq.Interrupts[0];
			}
			
			break;
		case ACPI_RESOURCE_TYPE_END_TAG:
			//device_printf(sc->dev, " - end parsing\n");
			break;

		default:
			device_printf(sc->dev, "unexpected type %d while parsing Current Resource Settings (_CSR)\n", res->Type);
			break;
	}

	return AE_OK;
}

static int
acpi_iichid_probe(device_t dev)
{
	if (acpi_disabled("iichid") || ACPI_ID_PROBE(device_get_parent(dev), dev, acpi_iichid_ids, NULL) > 0)
		return (ENXIO);

	device_set_desc(dev, "HID over I2C (ACPI)");

	return (BUS_PROBE_VENDOR);
}

static void
periodic_or_intr(void *context)
{
	struct acpi_iichid_softc *sc;

	sc = context;
	taskqueue_enqueue(sc->taskqueue, &sc->event_task);
}

static void
event_task(void *context, int pending)
{
	struct acpi_iichid_softc *sc;

	sc = context;

	mtx_lock(&sc->lock);

	struct iichid_softc *dsc;
	dsc = sc->iichid_sc;

	mtx_unlock(&sc->lock);

	dsc->event_handler(dsc, pending);

	mtx_lock(&sc->lock);
	if (sc->callout_setup && sc->sampling_rate > 0 && !callout_pending(&sc->periodic_callout) )
		callout_reset(&sc->periodic_callout, hz / sc->sampling_rate, periodic_or_intr, sc);
	mtx_unlock(&sc->lock);
}

static int
acpi_iichid_setup_callout(device_t dev, struct acpi_iichid_softc *sc)
{
	if (sc->sampling_rate < 0)
	{
		device_printf(dev, "sampling_rate is below 0, can't setup callout\n");
		return (EINVAL);
	}

	callout_init(&sc->periodic_callout, 1);
	sc->callout_setup=true;
	device_printf(dev, "successfully setup callout");
	return (0);
}

static int
acpi_iichid_reset_callout(device_t dev, struct acpi_iichid_softc *sc)
{
	if (sc->sampling_rate <= 0)
	{
		device_printf(dev, "sampling_rate is below or equal to 0, can't reset callout\n");
		return (EINVAL);
	}

	if (sc->callout_setup)
		callout_reset(&sc->periodic_callout, hz / sc->sampling_rate, periodic_or_intr, sc);
	else
		return (EINVAL);
	return (0);
}

static void
acpi_iichid_teardown_callout(device_t dev, struct acpi_iichid_softc *sc)
{
	callout_drain(&sc->periodic_callout);
	sc->callout_setup=false;
	device_printf(dev, "tore callout down\n");
}

static int
acpi_iichid_setup_interrupt(device_t dev, struct acpi_iichid_softc *sc)
{
	sc->irq_rid = 0;
	sc->irq_cookie = 0;
	sc->irq_res = 0;
	sc->irq_res = bus_alloc_resource_any(dev, SYS_RES_IRQ, &sc->irq_rid, RF_ACTIVE);

	if( sc->irq_res != NULL )
	{
		device_printf(dev, "allocated irq at 0x%jx and rid %d\n", (uintmax_t)sc->irq_res, sc->irq_rid);
		int error = bus_setup_intr(dev, sc->irq_res, INTR_TYPE_TTY | INTR_MPSAFE, NULL, periodic_or_intr, sc, &sc->irq_cookie);
		if (error != 0)
		{
			device_printf(dev, "Could not setup interrupt handler\n");
			bus_release_resource(dev, SYS_RES_IRQ, sc->irq_rid, sc->irq_res);
			return error;
		} else
			device_printf(dev, "successfully setup interrupt\n");

	} else {
		device_printf(dev, "could not allocate IRQ resource\n");
	}

	return (0);
}

static void
acpi_iichid_teardown_interrupt(device_t dev, struct acpi_iichid_softc *sc)
{
	if (sc->irq_cookie)
	{
		bus_teardown_intr(dev, sc->irq_res, sc->irq_cookie);
	}

	if (sc->irq_res)
	{
		bus_release_resource(dev, SYS_RES_IRQ, sc->irq_rid, sc->irq_res);
	}
	sc->irq_rid = 0;
	sc->irq_cookie = 0;
	sc->irq_res = 0;
}

static int
sysctl_sampling_rate_handler(SYSCTL_HANDLER_ARGS)
{
	int err, value, oldval;
	struct acpi_iichid_softc *sc;

	sc = arg1;	
	
	mtx_lock(&sc->lock);

	value = sc->sampling_rate;
	oldval = sc->sampling_rate;
	err = sysctl_handle_int(oidp, &value, 0, req);

	if (err != 0 || req->newptr == NULL || value == sc->sampling_rate)
	{
		mtx_unlock(&sc->lock);
		return (err);
	}

	sc->sampling_rate = value;

	if( oldval < 0 && value >= 0 )
	{
		acpi_iichid_teardown_interrupt(sc->dev, sc);
		acpi_iichid_setup_callout(sc->dev, sc);
	} else if ( oldval >=0 && value < 0)
	{
		acpi_iichid_teardown_callout(sc->dev, sc);
		acpi_iichid_setup_interrupt(sc->dev, sc);
	}

	if( value > 0 )
		acpi_iichid_reset_callout(sc->dev, sc);

	device_printf(sc->dev, "new sampling_rate value: %d\n", value);

	mtx_unlock(&sc->lock);

	return (0);
}

static int
acpi_iichid_attach(device_t dev)
{
	struct acpi_iichid_softc *sc;
	sc = device_get_softc(dev);

	mtx_init(&sc->lock, "HID over I2C (ACPI) lock", NULL, MTX_DEF);

	sc->dev = dev;

	sc->irq = 0;
	sc->irq_rid = 0;
	sc->irq_res = 0;
	sc->irq_cookie = 0;
	sc->sampling_rate = -1;
	sc->taskqueue = 0;
	sc->iichid_sc = 0;
	sc->callout_setup = false;

	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
		SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
		OID_AUTO, "sampling_rate", CTLTYPE_INT | CTLFLAG_RWTUN,
		sc, 0,
		sysctl_sampling_rate_handler, "I", "sampling rate in num/second");

	//get ACPI handles for current device and its parent
	ACPI_HANDLE ahnd = acpi_get_handle(dev),
		    phnd = NULL;

	if (!ahnd) {
		device_printf(dev, "Could not retrieve ACPI handle\n");
		mtx_destroy(&sc->lock);
		return (ENXIO);
	}

	//besides the ACPI parent handle, get the newbus parent
	device_t parent;

	if (ACPI_SUCCESS(AcpiGetParent(ahnd, &phnd)) && (parent = acpi_get_device(phnd)) && device_is_attached(parent))
	{
		//device_printf(dev, "my parent is a %s and its ACPI path is %s\n", device_get_driver(parent)->name, acpi_name(phnd));
	} else {
		device_printf(dev, "could not retrieve parent device or parent is not attached (driver loaded?)");
		mtx_destroy(&sc->lock);
		return (ENXIO);
	}


	//function (_DSM) to be evaluated to retrieve the address of the configuration register of the hi device
	/* 3cdff6f7-4267-4555-ad05-b30a3d8938de */
	static uint8_t acpi_iichid_dsm_guid[] = {
		0xF7, 0xF6, 0xDF, 0x3C, 0x67, 0x42, 0x55, 0x45,
		0xAD, 0x05, 0xB3, 0x0A, 0x3D, 0x89, 0x38, 0xDE,
	};

	//prepare 4 arguments
	ACPI_OBJECT obj[4];
	ACPI_OBJECT_LIST acpi_arg;

	ACPI_BUFFER acpi_buf;

	acpi_buf.Pointer = NULL;
	acpi_buf.Length = ACPI_ALLOCATE_BUFFER;

	acpi_arg.Pointer = &obj[0];
	acpi_arg.Count = 4;

	obj[0].Type = ACPI_TYPE_BUFFER;
	obj[0].Buffer.Length = sizeof(acpi_iichid_dsm_guid);
	obj[0].Buffer.Pointer = &acpi_iichid_dsm_guid[0];

	obj[1].Type = ACPI_TYPE_INTEGER;
	obj[1].Integer.Value = 1;

	obj[2].Type = ACPI_TYPE_INTEGER;
	obj[2].Integer.Value = 1;

	obj[3].Type = ACPI_TYPE_PACKAGE;
	obj[3].Package.Count = 0;

	//evaluate
	ACPI_STATUS status = ACPI_EVALUATE_OBJECT(device_get_parent(dev), dev, "_DSM", &acpi_arg, &acpi_buf);

	if (ACPI_FAILURE(status)) {
		device_printf(dev, "error evaluating _DSM\n");
		if (acpi_buf.Pointer != NULL)
			AcpiOsFree(acpi_buf.Pointer);
		mtx_destroy(&sc->lock);
		return (ENXIO);
	}

	//the result will contain the register address (int type)
	ACPI_OBJECT *result = (ACPI_OBJECT*)acpi_buf.Pointer;
	if( result->Type != ACPI_TYPE_INTEGER ) {
		device_printf(dev, "_DSM should return descriptor register address as integer\n");
		AcpiOsFree(result);
		mtx_destroy(&sc->lock);
		return (ENXIO);
	}

	//take it (much work done for one byte -.-)
	device_printf(dev, "descriptor register address is %jx\n", (uintmax_t)result->Integer.Value);
	sc->hw.config_reg = result->Integer.Value;

	//cleanup
	AcpiOsFree(result);

	//_CSR holds more data (device address and irq) and only needs a callback to evaluate its data
	status = AcpiWalkResources(ahnd, "_CRS", acpi_iichid_walk_handler, sc);

	if (ACPI_FAILURE(status)) {
		device_printf(dev, "could not evaluate _CRS\n");
		mtx_destroy(&sc->lock);
		return (ENXIO);
	}

	//get the full ACPI pathname of dev's parent
	acpi_buf.Pointer = NULL;
	acpi_buf.Length = ACPI_ALLOCATE_BUFFER;
	AcpiGetName(phnd, ACPI_FULL_PATHNAME, &acpi_buf);

	device_printf(dev, "parent device is \"%s\"\n", (const char*)acpi_buf.Pointer);
	AcpiOsFree(acpi_buf.Pointer);

	//padev will hold the newbus device handle of this (dev) devices ACPI parent, which is not necessarily the same as this (dev) devices parent.
	//I.e. both parent devices might even be on different branches of the device tree. The ACPI parent is most likely a iicbus
	//device (e.g. ig4's ig4iic_pci0), while the newbus parent of dev will in most cases acpi0.
	device_t padev = acpi_get_device(phnd);		//ACPI parent, the one we are interested in because it is a iicbus
#if 0
	device_t pbdev = device_get_parent(dev);	//newbus parent, just for reference

	device_printf(dev, "parent devices: 0x%lx (ACPI, %s) and 0x%lx (Newbus, %s)\n", (uint64_t)padev, device_get_name(padev), (uint64_t)pbdev, device_get_name(padev));
#endif
	//look below padev whether there already is a iichid device that can be reused or create a new one
	if (padev)
	{
		//the should be a iicbus device, nevertheless no KASSERT here since the system will continue to function
		// only iichid device won't operate
		device_t iicbus_dev = device_find_child(padev, "iicbus", -1);
		if (iicbus_dev)
		{
			device_t *children;
			int ccount;

			device_t dnew = NULL;

			//get a list of all children below iicbus and check if parameters match
			if (device_get_children(iicbus_dev, &children, &ccount) == 0)
			{
				for(int i=0; i<ccount; i++)
				{
					driver_t *drv = device_get_driver(children[i]);
					if (!drv)
						continue;

					if (strcmp(drv->name, "iichid") == 0)
					{
						struct iichid_softc *dsc = (struct iichid_softc*)device_get_softc(children[i]);
						if (	   dsc->hw.device_addr == sc->hw.device_addr
							&& dsc->hw.config_reg  == sc->hw.config_reg )
						{
							//reuse this child, there shouldn't be more than one
							//if there are more devices matching that is observable in dmesg
							dnew = children[i];
							device_printf(dev, "device %s ADDR 0x%x REG 0x%x already present on %s\n", device_get_nameunit(children[i]), dsc->hw.device_addr, dsc->hw.config_reg, device_get_nameunit(iicbus_dev));
						}
					}
				}
				free(children, M_TEMP);
			}

			//no iichid device found to be reused, so one is created and parameters are set
			if ( dnew == NULL )
			{
				//add child of type iichid below iicbus
				dnew = BUS_ADD_CHILD(iicbus_dev, 0, "iichid", -1);
				if (dnew)
				{
					//config register and device address via resource_list/ivars
					bus_set_resource(dnew, SYS_RES_IOPORT, 0, sc->hw.config_reg, 2);
					BUS_WRITE_IVAR(iicbus_dev, dnew, IICBUS_IVAR_ADDR, sc->hw.device_addr);

					//try and attach:
					if (device_probe_and_attach(dnew) == 0)
					{
						// success? print status and device configuration
						struct iichid_softc *dsc = (struct iichid_softc*)device_get_softc(dnew);
						device_printf(dev, "added %s ADDR 0x%x REG 0x%x to %s\n", device_get_nameunit(dnew), dsc->hw.device_addr, dsc->hw.config_reg, device_get_nameunit(iicbus_dev));
					} else {
						//failure? remove child, print error and leave
						device_printf(dev, "probe or attach failed for %s! (ADDR: 0x%x, REG: 0x%x)\n", device_get_nameunit(dnew), sc->hw.device_addr, sc->hw.config_reg);
						device_delete_child(iicbus_dev, dnew);
						mtx_destroy(&sc->lock);
						return (ENXIO);
					}
				} else {
					device_printf(dev, "could not attach iichid device to %s! (ADDR: 0x%x, REG: 0x%x)\n", device_get_nameunit(iicbus_dev), sc->hw.device_addr, sc->hw.config_reg);
					mtx_destroy(&sc->lock);
					return (ENXIO);
				}
			}

			if ( dnew != NULL )
			{
				struct iichid_softc *dsc = (struct iichid_softc*)device_get_softc(dnew);
				if (dsc)
				{
					sc->iichid_sc = dsc;
					TASK_INIT(&sc->event_task, 0, event_task, sc);

					sc->taskqueue = taskqueue_create("iichid_tq", M_NOWAIT | M_ZERO, taskqueue_thread_enqueue, &sc->taskqueue);
					if( sc->taskqueue == NULL )
					{
						return (ENXIO);
					}else{
						taskqueue_start_threads(&sc->taskqueue, 1, PI_TTY, "%s taskq", device_get_nameunit(sc->dev));
					}

					int error;
					if (sc->sampling_rate >= 0)
					{
						error = acpi_iichid_setup_callout(dev, sc);
						if (error != 0)
						{
							device_printf(dev, "please consider setting the sampling_rate sysctl to -1");
						}
					} else {
						error = acpi_iichid_setup_interrupt(dev, sc);
						if (error != 0)
						{
							device_printf(dev, "please consider setting the sampling_rate sysctl greater than 0.");
						}
					}
				}
			}
		}
	}



	return (0);			/* success */
}

static int
acpi_iichid_detach(device_t dev)
{
	//we leave the added devices below iicbus instances intact, since this module is only needed to parameterize
	// them. Afterwards they function without this
	struct acpi_iichid_softc *sc;
	sc = device_get_softc(dev);

	mtx_lock(&sc->lock);

	if (sc->taskqueue)
	{
		taskqueue_block(sc->taskqueue);
		taskqueue_drain(sc->taskqueue, &sc->event_task);
		taskqueue_free(sc->taskqueue);
	}

	acpi_iichid_teardown_callout(dev, sc);
	acpi_iichid_teardown_interrupt(dev, sc);

	mtx_unlock(&sc->lock);
	mtx_destroy(&sc->lock);
	return (0);
}

DRIVER_MODULE(acpi_iichid, acpi, acpi_iichid_driver, acpi_iichid_devclass, NULL, 0);
MODULE_DEPEND(acpi_iichid, acpi, 1, 1, 1);
MODULE_DEPEND(acpi_iichid, iicbus, IICBUS_MINVER, IICBUS_PREFVER, IICBUS_MAXVER);
MODULE_DEPEND(acpi_iichid, iichid, 1, 1, 1);
MODULE_VERSION(acpi_iichid, 1);
