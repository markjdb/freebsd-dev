#include <sys/stdint.h>
#include <sys/stddef.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/sysctl.h>
#include <sys/sx.h>
#include <sys/unistd.h>
#include <sys/callout.h>
#include <sys/malloc.h>
#include <sys/priv.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/sbuf.h>
#include <sys/endian.h>
#include <sys/rman.h>
#include <sys/uio.h>
#include <machine/resource.h>

#include <sys/ioccom.h>
#include <sys/filio.h>
#include <sys/tty.h>
#include <sys/mouse.h>
#include <dev/iicbus/input/iichid.h>
#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iic.h>
#include <dev/iicbus/iiconf.h>

#include "iicbus_if.h"

static device_probe_t		iichid_probe;
static device_attach_t		iichid_attach;
static device_detach_t		iichid_detach;

static devclass_t iichid_devclass;

static device_method_t iichid_methods[] = {
	DEVMETHOD(device_probe, iichid_probe),
	DEVMETHOD(device_attach, iichid_attach),
	DEVMETHOD(device_detach, iichid_detach),

	DEVMETHOD_END
};

static d_open_t iichid_open;
static d_close_t iichid_close;
static d_read_t iichid_read;
static d_write_t iichid_write;
static d_ioctl_t iichid_ioctl;

static struct cdevsw iichid_cdevsw = {
	.d_version	= D_VERSION,
	.d_open		= iichid_open,
	.d_close	= iichid_close,
	.d_read		= iichid_read,
	.d_write	= iichid_write,
	.d_ioctl	= iichid_ioctl,
	.d_name		= "iichid"
};

static driver_t iichid_driver = {
	.name = "iichid",
	.methods = iichid_methods,
	.size = sizeof(struct iichid_softc),
};

static int
iichid_fetch_buffer(device_t dev, uint8_t* cmd, int cmdlen, uint8_t *buf, int buflen)
{
	uint16_t addr = iicbus_get_addr(dev);
	struct iic_msg msgs[] = {
	     { addr << 1, IIC_M_WR | IIC_M_NOSTOP, cmdlen, cmd },
	     { addr << 1, IIC_M_RD, buflen, buf },
	};

	return (iicbus_transfer(dev, msgs, nitems(msgs)));
}

static int
iichid_fetch_report(device_t dev, struct i2c_hid_desc* hid_desc, uint8_t *data, int len, int *actual_len)
{
	struct iichid_softc* sc;
	sc = device_get_softc(dev);

	mtx_assert(&sc->lock, MA_OWNED);

	*actual_len = 0;

	uint16_t dtareg = htole16(hid_desc->wInputRegister);
			
	uint8_t cmd[] = {dtareg & 0xff, dtareg >> 8};
	int cmdlen    = 2;
	uint8_t buf[len];

	mtx_unlock(&sc->lock);

	int error = iichid_fetch_buffer(dev, cmd, cmdlen, buf, len);

	mtx_lock(&sc->lock);

	memcpy(data, buf, len);

	if (error != 0)
	{
		device_printf(dev, "could not retrieve input report (%d)\n", error);
		return error;
	}

	*actual_len = data[0] | data[1] << 8;

	return 0;
}

static int fetch_hid_descriptor(device_t dev)
{
	struct iichid_softc *sc = device_get_softc(dev);

	uint16_t cr = sc->hw.config_reg;
	return (iichid_fetch_buffer(dev, (uint8_t*)&cr, sizeof(cr), (uint8_t*)&sc->desc, sizeof(struct i2c_hid_desc)));
}

static int fetch_report_descriptor(device_t dev, uint8_t **buf, int *len)
{
	struct iichid_softc *sc = device_get_softc(dev);

	if (sc->desc.wHIDDescLength != 30)
		return -1;

	*buf = malloc(sc->desc.wReportDescLength, M_TEMP, M_NOWAIT | M_ZERO);
	*len = sc->desc.wReportDescLength;

	uint16_t rdr = sc->desc.wReportDescRegister;

	int error = (iichid_fetch_buffer(dev, (uint8_t*)&rdr, sizeof(rdr), *buf, sc->desc.wReportDescLength));

	return error;
}

static void
ms_hid_parse(device_t dev, const uint8_t *buf, uint16_t len, struct ms_info *info, uint8_t index)
{
	uint32_t flags;
	uint8_t i;
	uint8_t j;

	if (hid_locate(buf, len, HID_USAGE2(HUP_GENERIC_DESKTOP, HUG_X),
	    hid_input, index, &info->sc_loc_x, &flags, &info->sc_iid_x)) {

		if ((flags & MOUSE_FLAGS_MASK) == MOUSE_FLAGS) {
			info->sc_flags |= MS_FLAG_X_AXIS;
		}
	}
	if (hid_locate(buf, len, HID_USAGE2(HUP_GENERIC_DESKTOP, HUG_Y),
	    hid_input, index, &info->sc_loc_y, &flags, &info->sc_iid_y)) {

		if ((flags & MOUSE_FLAGS_MASK) == MOUSE_FLAGS) {
			info->sc_flags |= MS_FLAG_Y_AXIS;
		}
	}
	/* Try the wheel first as the Z activator since it's tradition. */
	if (hid_locate(buf, len, HID_USAGE2(HUP_GENERIC_DESKTOP,
	    HUG_WHEEL), hid_input, index, &info->sc_loc_z, &flags,
	    &info->sc_iid_z) ||
	    hid_locate(buf, len, HID_USAGE2(HUP_GENERIC_DESKTOP,
	    HUG_TWHEEL), hid_input, index, &info->sc_loc_z, &flags,
	    &info->sc_iid_z)) {
		if ((flags & MOUSE_FLAGS_MASK) == MOUSE_FLAGS) {
			info->sc_flags |= MS_FLAG_Z_AXIS;
		}
		/*
		 * We might have both a wheel and Z direction, if so put
		 * put the Z on the W coordinate.
		 */
		if (hid_locate(buf, len, HID_USAGE2(HUP_GENERIC_DESKTOP,
		    HUG_Z), hid_input, index, &info->sc_loc_w, &flags,
		    &info->sc_iid_w)) {

			if ((flags & MOUSE_FLAGS_MASK) == MOUSE_FLAGS) {
				info->sc_flags |= MS_FLAG_W_AXIS;
			}
		}
	} else if (hid_locate(buf, len, HID_USAGE2(HUP_GENERIC_DESKTOP,
	    HUG_Z), hid_input, index, &info->sc_loc_z, &flags, 
	    &info->sc_iid_z)) {

		if ((flags & MOUSE_FLAGS_MASK) == MOUSE_FLAGS) {
			info->sc_flags |= MS_FLAG_Z_AXIS;
		}
	}
	/*
	 * The Microsoft Wireless Intellimouse 2.0 reports it's wheel
	 * using 0x0048, which is HUG_TWHEEL, and seems to expect you
	 * to know that the byte after the wheel is the tilt axis.
	 * There are no other HID axis descriptors other than X,Y and
	 * TWHEEL
	 */
	if (hid_locate(buf, len, HID_USAGE2(HUP_GENERIC_DESKTOP,
	    HUG_TWHEEL), hid_input, index, &info->sc_loc_t, 
	    &flags, &info->sc_iid_t)) {

		info->sc_loc_t.pos += 8;

		if ((flags & MOUSE_FLAGS_MASK) == MOUSE_FLAGS) {
			info->sc_flags |= MS_FLAG_T_AXIS;
		}
	} else if (hid_locate(buf, len, HID_USAGE2(HUP_CONSUMER,
		HUC_AC_PAN), hid_input, index, &info->sc_loc_t,
		&flags, &info->sc_iid_t)) {

		if ((flags & MOUSE_FLAGS_MASK) == MOUSE_FLAGS)
			info->sc_flags |= MS_FLAG_T_AXIS;
	}
	/* figure out the number of buttons */

	for (i = 0; i < MS_BUTTON_MAX; i++) {
		if (!hid_locate(buf, len, HID_USAGE2(HUP_BUTTON, (i + 1)),
		    hid_input, index, &info->sc_loc_btn[i], NULL, 
		    &info->sc_iid_btn[i])) {
			break;
		}
	}

	/* detect other buttons */

	for (j = 0; (i < MS_BUTTON_MAX) && (j < 2); i++, j++) {
		if (!hid_locate(buf, len, HID_USAGE2(HUP_MICROSOFT, (j + 1)),
		    hid_input, index, &info->sc_loc_btn[i], NULL, 
		    &info->sc_iid_btn[i])) {
			break;
		}
	}

	info->sc_buttons = i;

	if (info->sc_flags == 0)
		return;

	/* announce information about the mouse */
	device_printf(dev, "%d buttons and [%s%s%s%s%s] coordinates ID=%u\n",
	    (info->sc_buttons),
	    (info->sc_flags & MS_FLAG_X_AXIS) ? "X" : "",
	    (info->sc_flags & MS_FLAG_Y_AXIS) ? "Y" : "",
	    (info->sc_flags & MS_FLAG_Z_AXIS) ? "Z" : "",
	    (info->sc_flags & MS_FLAG_T_AXIS) ? "T" : "",
	    (info->sc_flags & MS_FLAG_W_AXIS) ? "W" : "",
	    info->sc_iid_x);
}

static int
iichid_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct iichid_softc *sc = dev->si_drv1;

	mtx_lock(&sc->lock);
	if (sc->isopen)
	{
		mtx_unlock(&sc->lock);
		return (EBUSY);
	}
	
	sc->isopen = true;
	sc->bytesread = sc->sc_mode.packetsize;


	while (!STAILQ_EMPTY(&sc->ms_queue))
	{
		struct ms_tx_entry *u = STAILQ_FIRST(&sc->ms_queue);
		STAILQ_REMOVE_HEAD(&sc->ms_queue, next);
		STAILQ_INSERT_HEAD(&sc->ms_unused_blocks, u, next);
	}

	mtx_unlock(&sc->lock);

	return 0;
}

static int
iichid_close(struct cdev *dev, int fflags, int devtype, struct thread *td)
{
	struct iichid_softc *sc = dev->si_drv1;

	cv_broadcastpri(&sc->cv, 0);

	mtx_lock(&sc->lock);
	sc->isopen=false;
	mtx_unlock(&sc->lock);

	return 0;
}

static int
iichid_write(struct cdev *dev, struct uio *uio, int ioflags)
{
	return 0;
}

static int
iichid_read(struct cdev *dev, struct uio* uio, int ioflags)
{
	struct iichid_softc *sc = dev->si_drv1;

	mtx_lock(&sc->lock);

	while (!sc->detaching && STAILQ_EMPTY(&sc->ms_queue) && sc->bytesread == sc->sc_mode.packetsize)
	{
		int error = cv_wait_sig(&sc->cv, &sc->lock);
		if (error != 0)
		{
			mtx_unlock(&sc->lock);
			return error;
		}
	}
	
	if (sc->detaching)
	{
		mtx_unlock(&sc->lock);
		return ENXIO;
	}

	if (sc->bytesread == sc->sc_mode.packetsize && !STAILQ_EMPTY(&sc->ms_queue))
	{
		struct ms_tx_entry *u = STAILQ_FIRST(&sc->ms_queue);
		STAILQ_REMOVE_HEAD(&sc->ms_queue, next);
		memcpy(&sc->rbuf, u, sizeof(struct ms_tx_entry));
		sc->bytesread = 0;

		STAILQ_INSERT_TAIL(&sc->ms_unused_blocks, u, next);
	}
	mtx_unlock(&sc->lock);
	
	int error = uiomove(sc->rbuf.buf+sc->bytesread, 1, uio);
	sc->bytesread++;
	if (error != 0)
		device_printf(sc->dev, "I could not be read from");
	
	return 0;
}

static int
iichid_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flag, struct thread *td)
{	
	struct iichid_softc *sc = dev->si_drv1;
	int error = 0;
	mousemode_t mode;

	mtx_lock(&sc->lock);

	switch (cmd) {
	case MOUSE_SETMODE:
		mode = *(mousemode_t*)data;

		if (mode.level == -1) {
			/* don't change the current setting */
		} else if ((mode.level < 0) || (mode.level > 1)) {
			error = EINVAL;
			break;
		} else {
			sc->sc_mode.level = mode.level;
		}

		if (sc->sc_mode.level == 0) {
			if (sc->sc_hw.buttons > MOUSE_MSC_MAXBUTTON)
				sc->sc_hw.buttons = MOUSE_MSC_MAXBUTTON;
	
			sc->sc_mode.protocol = MOUSE_PROTO_MSC;
			sc->sc_mode.packetsize = MOUSE_MSC_PACKETSIZE;
			sc->sc_mode.syncmask[0] = MOUSE_MSC_SYNCMASK;
			sc->sc_mode.syncmask[1] = MOUSE_MSC_SYNC;
		} else if (sc->sc_mode.level == 1) {
			if (sc->sc_hw.buttons > MOUSE_SYS_MAXBUTTON)
				sc->sc_hw.buttons = MOUSE_SYS_MAXBUTTON;

			sc->sc_mode.protocol = MOUSE_PROTO_SYSMOUSE;
			sc->sc_mode.packetsize = MOUSE_SYS_PACKETSIZE;
			sc->sc_mode.syncmask[0] = MOUSE_SYS_SYNCMASK;
			sc->sc_mode.syncmask[1] = MOUSE_SYS_SYNC;
		}
		break;
	case MOUSE_SETLEVEL:
		if (*(int *)data < 0 || *(int *)data > 1) {
			error = EINVAL;
			break;
		}
		sc->sc_mode.level = *(int *)data;

		if (sc->sc_mode.level == 0) {
			if (sc->sc_hw.buttons > MOUSE_MSC_MAXBUTTON)
				sc->sc_hw.buttons = MOUSE_MSC_MAXBUTTON;

			sc->sc_mode.protocol = MOUSE_PROTO_MSC;
			sc->sc_mode.packetsize = MOUSE_MSC_PACKETSIZE;
			sc->sc_mode.syncmask[0] = MOUSE_MSC_SYNCMASK;
			sc->sc_mode.syncmask[1] = MOUSE_MSC_SYNC;
		} else if (sc->sc_mode.level == 1) {
			if (sc->sc_hw.buttons > MOUSE_SYS_MAXBUTTON)
				sc->sc_hw.buttons = MOUSE_SYS_MAXBUTTON;

			sc->sc_mode.protocol = MOUSE_PROTO_SYSMOUSE;
			sc->sc_mode.packetsize = MOUSE_SYS_PACKETSIZE;
			sc->sc_mode.syncmask[0] = MOUSE_SYS_SYNCMASK;
			sc->sc_mode.syncmask[1] = MOUSE_SYS_SYNC;
		}
		break;
	case MOUSE_GETHWINFO:
		*(mousehw_t *)data = sc->sc_hw;
		break;

	case MOUSE_GETMODE:
		*(mousemode_t *)data = sc->sc_mode;
		break;

	case MOUSE_GETLEVEL:
		*(int *)data = sc->sc_mode.level;
		break;

	case MOUSE_GETSTATUS:{
		mousestatus_t *status = (mousestatus_t *)data;

		*status = sc->sc_status;
		sc->sc_status.obutton = sc->sc_status.button;
		sc->sc_status.button = 0;
		sc->sc_status.dx = 0;
		sc->sc_status.dy = 0;
		sc->sc_status.dz = 0;
		/* sc->sc_status.dt = 0; */

		if (status->dx || status->dy || status->dz /* || status->dt */ ) {
			status->flags |= MOUSE_POSCHANGED;
		}
		if (status->button != status->obutton) {
			status->flags |= MOUSE_BUTTONSCHANGED;
		}
		break;
		}
	default:
		error = ENOTTY;
		break;
	}

	mtx_unlock(&sc->lock);
	return (error);
}

static void
ms_put_queue(struct iichid_softc *sc, int32_t dx, int32_t dy,
    int32_t dz, int32_t dt, int32_t buttons)
{
	if (dx > 254)
		dx = 254;
	if (dx < -256)
		dx = -256;
	if (dy > 254)
		dy = 254;
	if (dy < -256)
		dy = -256;
	if (dz > 126)
		dz = 126;
	if (dz < -128)
		dz = -128;
	if (dt > 126)
		dt = 126;
	if (dt < -128)
		dt = -128;

	if (sc->invert != 0)
		dz = -dz;
	if (!STAILQ_EMPTY(&sc->ms_unused_blocks))
	{
		struct ms_tx_entry *u = STAILQ_FIRST(&sc->ms_unused_blocks);
		STAILQ_REMOVE_HEAD(&sc->ms_unused_blocks, next);

		u->buf[0] = MOUSE_MSC_SYNC;
		u->buf[0] |= (~buttons) & MOUSE_MSC_BUTTONS;
		u->buf[1] = dx >> 1;
		u->buf[2] = dy >> 1;
		u->buf[3] = dx - (dx >> 1);
		u->buf[4] = dy - (dy >> 1);

		if (sc->sc_mode.level == 1) {
			u->buf[5] = dz >> 1;
			u->buf[6] = dz - (dz >> 1);
			u->buf[7] = (((~buttons) >> 3) & MOUSE_SYS_EXTBUTTONS);
		}

		STAILQ_INSERT_TAIL(&sc->ms_queue, u, next);
	} else {
		device_printf(sc->dev, "no blocks available\n");
	}
}

static void
iichid_event(void* context, int pending)
{
	struct iichid_softc *sc = context;

	mtx_lock(&sc->lock);

	int actual = 0;
	int error = iichid_fetch_report(sc->dev, &sc->desc, sc->input_buf, sc->input_size, &actual);

	if (error != 0)
	{
		device_printf(sc->dev, "an error occured\n");
		mtx_unlock(&sc->lock);
		return;
	}

	if (actual <= 0)
	{
		device_printf(sc->dev, "no data received\n");
		mtx_unlock(&sc->lock);
		return;
	}

	int32_t dw = 0;
	int32_t dx = 0;
	int32_t dy = 0;
	int32_t dz = 0;
	int32_t dt = 0;
	int32_t buttons = 0;
	int32_t buttons_found = 0;
	uint8_t id = 0;

	uint8_t *buf = sc->input_buf;
	buf++; buf++;
	int len = actual;

	if (sc->sc_iid)
	{
		id = *buf;
		buf++;
		len--;
	}

//	device_printf(sc->dev, "id: %d\n", id);

	for(int i=0; i<MS_INFO_MAX; i++)
	{
		struct ms_info *info = &sc->info[i];
		if ((info->sc_flags & MS_FLAG_W_AXIS) &&
		    (id == info->sc_iid_w))
			dw += hid_get_data(buf, len, &info->sc_loc_w);

		if ((info->sc_flags & MS_FLAG_X_AXIS) && 
		    (id == info->sc_iid_x))
			dx += hid_get_data(buf, len, &info->sc_loc_x);

		if ((info->sc_flags & MS_FLAG_Y_AXIS) &&
		    (id == info->sc_iid_y))
			dy -= hid_get_data(buf, len, &info->sc_loc_y);

		if ((info->sc_flags & MS_FLAG_Z_AXIS) &&
		    (id == info->sc_iid_z)) {
			int32_t temp;
			temp = hid_get_data(buf, len, &info->sc_loc_z);
			dz -= temp;
		}

		if ((info->sc_flags & MS_FLAG_T_AXIS) &&
		    (id == info->sc_iid_t)) {
			dt -= hid_get_data(buf, len, &info->sc_loc_t);
			/* T-axis is translated into button presses */
			buttons_found |= (1UL << 5) | (1UL << 6);
		}

		for (i = 0; i < info->sc_buttons; i++) {
			uint32_t mask;
			mask = 1UL << MS_BUT(i);
			/* check for correct button ID */
			if (id != info->sc_iid_btn[i])
				continue;
			/* check for button pressed */
			if (hid_get_data(buf, len, &info->sc_loc_btn[i]))
				buttons |= mask;
			/* register button mask */
			buttons_found |= mask;
		}
		
		buttons |= sc->sc_status.button & ~buttons_found;

		if (dx || dy || dz || dt || dw ||
		    (buttons != sc->sc_status.button)) {

			/* translate T-axis into button presses until further */
			if (dt > 0) {
				ms_put_queue(sc, 0, 0, 0, 0, buttons);
				buttons |= 1UL << 5;
			} else if (dt < 0) {
				ms_put_queue(sc, 0, 0, 0, 0, buttons);
				buttons |= 1UL << 6;
			}

			sc->sc_status.button = buttons;
			sc->sc_status.dx += dx;
			sc->sc_status.dy += dy;
			sc->sc_status.dz += dz;

			//device_printf(sc->dev, "dx: %d, dy: %d, dz: %d, dt: %d, dw: %d, btn: 0x%2x\n", dx, dy, dz, dt, dw, buttons);

			ms_put_queue(sc, dx, dy, dz, dt, buttons);
		}
	}

//	device_printf(sc->dev, "read: %d/%d\n", actual, sc->desc.wMaxInputLength);
	mtx_unlock(&sc->lock);

	cv_signal(&sc->cv);
}

static int
iichid_probe(device_t dev)
{
	device_t pdev = device_get_parent(dev);

	if (!pdev)
		return (ENXIO);

	driver_t *pdrv = device_get_driver(pdev);

	if (!pdrv)
		return (ENXIO);

	if (strcmp(pdrv->name, "iicbus") != 0)
		return (ENXIO);

	device_set_desc(dev, "HID over I2C");

	return (BUS_PROBE_VENDOR);
}

static int
sysctl_invert_handler(SYSCTL_HANDLER_ARGS)
{
	int err, value;
	struct iichid_softc *sc;

	sc = arg1;      
	
	mtx_lock(&sc->lock);

	value = sc->invert;
	err = sysctl_handle_int(oidp, &value, 0, req);

	if (err != 0 || req->newptr == NULL || value == sc->invert)
	{
		mtx_unlock(&sc->lock);
		return (err);
	}

	sc->invert = value;

	mtx_unlock(&sc->lock);

	return (0);
}

static int
iichid_attach(device_t dev)
{
	struct iichid_softc *sc = device_get_softc(dev);

	uintptr_t addr = 0, cr = 0;
	int error;

	sc->dev = dev;
	sc->detaching = false;
	sc->input_buf = NULL;
	sc->isopen = 0;
	sc->invert = 0;

	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
		SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
		OID_AUTO, "invert_scroll", CTLTYPE_INT | CTLFLAG_RWTUN,
		sc, 0,
		sysctl_invert_handler, "I", "invert mouse axis");

	// the config register is passed as resources, while the device address will always have a place in the iicbus child's (ivars) heart
	bus_get_resource(dev, SYS_RES_IOPORT, 0, (rman_res_t*)&cr, NULL);
	BUS_READ_IVAR(device_get_parent(dev), dev, IICBUS_IVAR_ADDR, &addr);

	// store the value in device's softc to have easy access
	// values only have 1 byte length, still make the casts explicit
	sc->hw.device_addr = (uint8_t)addr;
	sc->hw.config_reg = (uint16_t)cr;

	sc->event_handler = iichid_event;

	sc->cdev = make_dev(&iichid_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "ims%d", device_get_unit(dev));
	sc->cdev->si_drv1 = sc;

	device_printf(dev, "ADDR 0x%x REG 0x%x\n", sc->hw.device_addr, sc->hw.config_reg);

	if ( (error = fetch_hid_descriptor(dev)) != 0 )
	{
		iichid_detach(dev);
		device_printf(dev, "could not retrieve HID descriptor from device: %d\n", error);
	}

	uint8_t *rdesc;
	int len;

	if ( (error = fetch_report_descriptor(dev, &rdesc, &len)) != 0 )
	{
		iichid_detach(dev);
		device_printf(dev, "could not retrieve report descriptor from device: %d\n", error);
	}

	sc->input_size = sc->desc.wMaxInputLength;
	sc->input_buf = malloc(sc->desc.wMaxInputLength, M_DEVBUF, M_NOWAIT | M_ZERO);

	for (int i = 0; i < MS_INFO_MAX; i++) {
		ms_hid_parse(dev, rdesc, len, &sc->info[0], 0);
	}

	int isize = hid_report_size(rdesc, len, hid_input, &sc->sc_iid);


	if (isize+2 != sc->desc.wMaxInputLength)
		device_printf(dev, "determined (len=%d) and described (len=%d) input report lengths mismatch\n", isize+2, sc->desc.wMaxInputLength);

	mtx_init(&sc->lock, "iichid spin-lock", NULL, MTX_DEF);
	cv_init(&sc->cv, "iichid cv");

	sc->sc_hw.buttons = -1;
	sc->sc_hw.iftype = MOUSE_IF_SYSMOUSE;
	sc->sc_hw.type = MOUSE_MOUSE;
	sc->sc_hw.model = MOUSE_MODEL_GENERIC;
	sc->sc_hw.hwid = sc->desc.wVendorID; 

	sc->sc_mode.protocol = MOUSE_PROTO_SYSMOUSE;
	sc->sc_mode.rate = -1;
	sc->sc_mode.resolution = -1;
	sc->sc_mode.accelfactor = 1;
	sc->sc_mode.level = 0;
	sc->sc_mode.packetsize = MOUSE_SYS_PACKETSIZE;

	STAILQ_INIT(&sc->ms_queue);
	STAILQ_INIT(&sc->ms_unused_blocks);
	for(int i=0; i<MS_BUFQ_MAXLEN; i++)
	{
		struct ms_tx_entry *u = malloc(sizeof(struct ms_tx_entry), M_DEVBUF, M_NOWAIT | M_ZERO);
		STAILQ_INSERT_TAIL(&sc->ms_unused_blocks, u, next);
	}

//	device_printf(dev, "len: %d\nbcdVer: %d\nreport len: %d\ninput len: %d\nvid: 0x%x\npid: 0x%x\n", hid_desc.wHIDDescLength, hid_desc.bcdVersion, hid_desc.wReportDescLength, hid_desc.wMaxInputLength, hid_desc.wVendorID, hid_desc.wProductID);

	return (0);			/* success */
}

static int
iichid_detach(device_t dev)
{
	struct iichid_softc *sc = device_get_softc(dev);
	if (sc)
	{
		if (sc->isopen)
			return (EBUSY);

		mtx_lock(&sc->lock);
		sc->detaching = true;
		mtx_unlock(&sc->lock);
		cv_broadcastpri(&sc->cv,0);
		if (mtx_initialized(&sc->lock))
		{
			mtx_destroy(&sc->lock);
		}

		struct ms_tx_buf* queues[2] = {&sc->ms_queue, &sc->ms_unused_blocks};
		for(int i=0; i<2; i++)
		{
			while (!STAILQ_EMPTY(queues[i]))
			{
				struct ms_tx_entry *u = STAILQ_FIRST(queues[i]);
				STAILQ_REMOVE_HEAD(queues[i], next);
				free(u, M_DEVBUF);
			}
		}

		if (sc->cdev)
			destroy_dev(sc->cdev);

		if (sc->input_buf)
			free(sc->input_buf, M_DEVBUF);
	}
	return (0);
}

DRIVER_MODULE(iichid, iicbus, iichid_driver, iichid_devclass, NULL, 0);
MODULE_DEPEND(iichid, iicbus, IICBUS_MINVER, IICBUS_PREFVER, IICBUS_MAXVER);
MODULE_VERSION(iichid, 1);
