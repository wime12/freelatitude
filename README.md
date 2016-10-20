# FreeBSD 11 on the Dell Latitude E7440

## Installation

The SSD does not support NCQ TRIM. But it supports TRIM. If you do not
switch off NCQ during the installation the data written on the disk
will be corrupted and the installation will fail. Therefore before
booting the kernel at the loader prompt type

	kern.cam.ada.0.quirks="0x2"

to switch off NCQ for the SSD. Be careful to do this everytime you
boot the installation medium.

After the installation before rebooting open a shell in the freshly
installed system and put the line above into `/boot/loader.conf`. Otherwise
your installed system will be corrupted sooner or later after you boot
into it.


## Power saving

I put

    kern.hz=100

into `/boot/loader.conf` but did not investigate its effect.

Be sure that `/boot/device.hints` contains

    hint.acpi_throttle.0.disabled="1"
    hint.p4tcc.0.disabled="1"

Add the lines if they are not there.

For power saving of the graphics card and the sound system and of PCI devices 
for which there is no driver add

    drm.i915.enable_rc6=7
    hw.snd.latency=7
    hw.pci.do_power_nodriver=3

to `/boot/loader.conf`.

And finally activate `powerd` in `/etc/rc.conf`:

    powerd_enable="YES"
    economy_cx_lowest="Cmax"
    performance_cx_lowest="Cmax"

It is vital that the graphics drivers are *not* loaded during boot but by
adding them to the `kld_list` in `/etc/rc.conf`:

    kld_list+='drm2 i915kms'

I experienced failures of `powerd` if I did otherwise; the power
consumption when running on battery never dropped below 14 W if the
loader loaded the modules. If they were loaded later I get between 9 W
and 10 W of power consumption. The maximum battery life is more than five
hours.


## Network failover

Network failover mode is achieved by configuring the `lagg` interface.
The built in WiFi card uses the `iwm` driver. Apparently either the
driver or the card does not like if its ethernet address is changed.
The connection to the network cannot be established. So the ethernet
interface of the network card has to be changed.

The following lines in `/etc/rc.conf` produce a working failover
configuration of the WiFi and the network card.

    ifconfig_em0="up"
    ifconfig_emo_alias0="ether xx:xx:xx:xx:xx:xx"
    wlans_iwm0="wlan0"
    ifconfig_wlan0="WPA"
    cloned_interfaces="lagg0"
    ifconfig_lagg0="laggproto failover laggport em0 laggport wlan0 DHCP"

`xx:xx:xx:xx:xx:xx` stands for the ethernet address of the WiFi card.
It can be found with `ifconfig`. Comment out the second and the last
two lines above and restart the system. `ifconfig` will show you the
ehternet address of `wlan0`.


## Suspend/Resume

Works mostly. If you suspend while the first terminal is active the
screen stays black. Just switch to any of the other terminals and back
and the screen will light up again.

Sometimes after resume no keyboard input is possible and the mouse
pointer does not react. I think this is a problem with the graphics
driver module `i915kms`. Maybe this will be resolved in future
versions.

Suspend/Resume does not require a reset of the video stack. Therefore
set it to `0` in `/boot/loader.conf`

    hw.acpi.reset_video="0"

which is the default anyway.


## Blue keys

Some keys with blue symbols are sent by the keyboard and some by ACPI.
I chose to send notifications about key presses to `devd` so that the
user can call any scripts or programs that she wishes.


