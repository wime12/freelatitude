# $Id: Makefile,v 1.1 2005/06/23 00:30:50 max Exp $
# $FreeBSD: releng/11.0/sys/modules/kbdmux/Makefile 297685 2016-04-07 20:12:45Z emaste $

# .PATH: ${.CURDIR}/../../dev/kbdmux
# .PATH: /usr/src/sys/dev/kbdmux
.PATH: .

KMOD=	kbdmxe
SRCS=	kbdmxe.c opt_compat.h opt_kbd.h opt_kbdmxe.h bus_if.h device_if.h

.if !defined(KERNBUILDDIR)
opt_compat.h:
	echo "#define COMPAT_FREEBSD6 1" > ${.TARGET}

opt_kbd.h:
	echo "#define KBD_INSTALL_CDEV 1" > ${.TARGET}
.endif

.include <bsd.kmod.mk>
