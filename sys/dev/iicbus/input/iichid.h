/* $OpenBSD: iichid.h,v 1.4 2016/01/31 18:24:35 jcs Exp $ */
/*
 * HID-over-i2c driver
 *
 * Copyright (c) 2015, 2016 joshua stein <jcs@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _IIC_HID_H_
#define	_IIC_HID_H_

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbhid.h>
#include <sys/mouse.h>
#include <sys/condvar.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

/* 5.1.1 - HID Descriptor Format */
struct i2c_hid_desc {
	uint16_t wHIDDescLength;
	uint16_t bcdVersion;
	uint16_t wReportDescLength;
	uint16_t wReportDescRegister;
	uint16_t wInputRegister;
	uint16_t wMaxInputLength;
	uint16_t wOutputRegister;
	uint16_t wMaxOutputLength;
	uint16_t wCommandRegister;
	uint16_t wDataRegister;
	uint16_t wVendorID;
	uint16_t wProductID;
	uint16_t wVersionID;
	uint32_t reserved;
} __packed;

#define	MOUSE_FLAGS_MASK (HIO_CONST|HIO_RELATIVE)
#define	MOUSE_FLAGS (HIO_RELATIVE)

#define	MS_BUF_SIZE      8		/* bytes */
#define	MS_BUFQ_MAXLEN   100		/* units */
#define	MS_BUTTON_MAX   31		/* exclusive, must be less than 32 */
#define	MS_BUT(i) ((i) < 3 ? (((i) + 2) % 3) : (i))
#define	MS_INFO_MAX	  2		/* maximum number of HID sets */

struct ms_info {
	struct hid_location sc_loc_w;
	struct hid_location sc_loc_x;
	struct hid_location sc_loc_y;
	struct hid_location sc_loc_z;
	struct hid_location sc_loc_t;
	struct hid_location sc_loc_btn[MS_BUTTON_MAX];

	uint32_t sc_flags;
#define	MS_FLAG_X_AXIS     0x0001
#define	MS_FLAG_Y_AXIS     0x0002
#define	MS_FLAG_Z_AXIS     0x0004
#define	MS_FLAG_T_AXIS     0x0008
#define	MS_FLAG_SBU        0x0010	/* spurious button up events */
#define	MS_FLAG_REVZ	   0x0020	/* Z-axis is reversed */
#define	MS_FLAG_W_AXIS     0x0040

	uint8_t	sc_iid_w;
	uint8_t	sc_iid_x;
	uint8_t	sc_iid_y;
	uint8_t	sc_iid_z;
	uint8_t	sc_iid_t;
	uint8_t	sc_iid_btn[MS_BUTTON_MAX];
	uint8_t	sc_buttons;
};

struct iichid_hw {
	uint8_t device_addr;
	uint16_t config_reg;
};

struct ms_tx_entry {
	STAILQ_ENTRY(ms_tx_entry) next;
	uint8_t buf[MS_BUF_SIZE];
};

STAILQ_HEAD(ms_tx_buf, ms_tx_entry);

struct iichid_softc {
	device_t dev;
	struct cdev *cdev;
	bool isopen;
	struct ms_tx_entry rbuf;
	uint8_t bytesread;

	struct ms_tx_buf ms_unused_blocks;
	struct ms_tx_buf ms_queue;

	struct iichid_hw hw;

	task_fn_t *event_handler;

	struct i2c_hid_desc desc;
	struct ms_info info[MS_INFO_MAX];
	uint8_t sc_iid;
	mousehw_t sc_hw;
	mousestatus_t sc_status;
	mousemode_t sc_mode;
	struct mtx lock;

	struct cv cv;
	bool detaching;

	int invert;

	uint8_t *input_buf;
	int input_size;
};

struct acpi_iichid_softc {
	device_t dev;
	struct cdev *sc_devnode;

	struct iichid_hw hw;

	uint16_t irq;
	int irq_rid;
	struct resource* irq_res;
	void* irq_cookie;
	struct iichid_softc* iichid_sc;

	int sampling_rate;
	struct callout periodic_callout;
	bool callout_setup;

	struct taskqueue* taskqueue;
	struct task event_task;

	struct mtx lock;
};

int acpi_iichid_get_report(device_t dev, struct i2c_hid_desc* hid_desc, enum hid_kind type, int id, void *data, int len);


#endif					/* _IIC_HID_H_ */
