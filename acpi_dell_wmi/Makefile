.PATH:	${.CURDIR}

KMOD=	acpi_dell_wmi
CFLAGS+=-I${.CURDIR}
SRCS=	acpi_dell_wmi.c opt_acpi.h acpi_if.h acpi_wmi_if.h device_if.h bus_if.h

.include <bsd.kmod.mk>
