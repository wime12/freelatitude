# FreeBSD 11 on the Dell Latitude E7440

## Installation

The SSD does not support NCQ TRIM. But it supports TRIM. If you do
not switch off NCQ during the installation the data written on the
disk will be corrupted and the installation will fail. Therefore
before booting the kernel at the loader prompt type

	`kern.cam.ada.0.quirks="0x2"`

to switch off NCQ for the SSD. Be careful to do this everytime you
boot the installation medium.

After the installation before rebooting open a shell in the freshly
installed system and put the line above into `/boot/loader.conf`.
Otherwise your installed system will be corrupted sooner or later
after you boot into it.


## Power saving

Be sure that `/boot/device.hints` contains

    `hint.acpi_throttle.0.disabled="1"`
    `hint.p4tcc.0.disabled="1"`

Add the lines if they are not there.

For power saving of the graphics card and the sound system and of
PCI devices for which there is no driver add

    `drm.i915.enable_rc6=7`
    `hw.snd.latency=7`
    `hw.pci.do_power_nodriver=3`

to `/boot/loader.conf`.

And finally activate `powerd` in `/etc/rc.conf`:

    `powerd_enable="YES"`
    `economy_cx_lowest="Cmax"`
    `performance_cx_lowest="Cmax"`

It is vital that the graphics drivers are *not* loaded during boot
but by adding them to the `kld_list` in `/etc/rc.conf`:

    `kld_list+=' i915kms'`

I experienced failures of `powerd` if I did otherwise; the power
consumption when running on battery never dropped below 14 W if the
boot loader loaded the modules. If they were loaded later I got
between 9 W and 10 W of power consumption.


## Network failover

Network failover mode is achieved by configuring the `lagg` interface.
The built in wifi card uses the `iwm` driver. Apparently either the
driver or the card does not like if its ethernet address is changed.
The connection to the network cannot be established. So the ethernet
interface of the network card has to be changed.

The following lines in `/etc/rc.conf` produce a working failover
configuration of the wifi and the network card.

    ```ifconfig_em0="up"
    ifconfig_emo_alias0="ether xx:xx:xx:xx:xx:xx"
    wlans_iwm0="wlan0"
    ifconfig_wlan0="WPA" cloned_interfaces="lagg0"
    ifconfig_lagg0="laggproto failover laggport em0 laggport wlan0 DHCP"`

`xx:xx:xx:xx:xx:xx` stands for the ethernet address of the wifi
card.  It can be found with `ifconfig`. Comment out the second and
the last two lines above and restart the system. `ifconfig` will
show you the ethernet address of `wlan0`.


## Suspend/Resume

Works mostly. If you suspend while the first terminal is active the
screen stays black. Just switch to any of the other terminals and
back and the screen will light up again.

Sometimes after resume no keyboard input is possible and the mouse
pointer does not react. I think this is a problem with the graphics
driver module `i915kms`. Maybe this will be resolved in future
versions.

Suspend/Resume does not require a reset of the video stack. Therefore
set it to `0` in `/boot/loader.conf`

    `hw.acpi.reset_video="0"`

which is the default anyway.


## Blue keys

Some keys with blue symbols are sent by the keyboard and some by
ACPI.  Therefore I wrote the kernel module `acpi_dell_wmi` and
`kbdmxe` which is a modified version of `kbdmux`. Just say `make`
in each directory of the modules and copy the resulting `.ko`
files to `/boot/modules/`.

Load the modules in the usual way by adding either

    `acpi_dell_wmi_load="YES"`

to `/boot/loader.conf` or by adding the line

    `kld_list+=' acpi_dell_wmi'`

to `/etc/rc.conf`.

Leave kbdmxe, don't compile it, with it keyboard doesn't work in X11.
KBDMXE here is ACPI subsystem in devd; it controls Media buttons(pause, prev, next, Volume Up/Down). 
Those can work without KBDMXE, just bind it in your DE/WM to corresponding script in control-tools/ directory. 

To be able to control the LCD brightness we need the functionality
of the kernel module `acpi_video`. Unfortunately it reacts on the
brightness keys by itself in a strange way. Apparently it cannot
determine the correct table of the display brightnesses. Therefore
there is an altered version `acpi_video_dell` in this repository
which you should build and copy to `/boot/modules/` and load it in
the usual way with

    `acpi_video_dell_load="YES"`

in `/boot/loader.conf` or by adding the module to the list in
`/etc/rc.conf`

    `kld_list+=' acpi_video_dell"`

An example of how `devd` can be configure to react on the various
notifications delivered by `kbdmxe` and `acpi_dell_wmi` is shown
in the file `dell.conf` in the `devd` directory of this
repository. Just copy the file to `/usr/local/etc/dev/` and also
the directory `control-tools/` to `/usr/local/libexec/`.

This example requires `intel_backlight` to be installed and
`musicpd` to be installed and configured.

Finally here is the table with the associations of the keys on
the keyboard and the notifications delivered to devd:

Key              | system | subsystem | type  | notify  | Description
---------------- | ------ | --------- | ----  | ------- | -----------------------------------
\<Fn> + \<UP>    | ACPI   | DELL      | KEY   | DSPBRUP | increase brightness of the display
\<Fn> + \<DOWN>  | ACPI   | DELL      | KEY   | DSPBRDN | decrease brightness of the display
\<Fn> + \<RIGHT> | ACPI   | DELL      | KEY   | KBBLCYC | cycle keyboard backlight brightness
\<Fn> + Q        | ACPI   | DELL      | KEY   | FNQ     |
\<Fn> + W        | ACPI   | DELL      | KEY   | FNW     |
\<Fn> + E        | ACPI   | DELL      | KEY   | FNE     |
\<Fn> + R        | ACPI   | DELL      | KEY   | FNR     |
\<Fn> + T        | ACPI   | DELL      | KEY   | FNT     |
\<Fn> + A        | ACPI   | DELL      | KEY   | FNA     |
\<Fn> + S        | ACPI   | DELL      | KEY   | FNS     |
\<Fn> + D        | ACPI   | DELL      | KEY   | FND     |
\<Fn> + F        | ACPI   | DELL      | KEY   | FNF     |
\<Fn> + G        | ACPI   | DELL      | KEY   | FNG     |
                 | ACPI   | DELL      | EVENT | KBBLOFF | keyboard backlight is off
                 | ACPI   | DELL      | EVENT | KBBLLV1 | keyboard backlight at level 1
                 | ACPI   | DELL      | EVENT | KBBLLV2 | keyboard backlight at level 2
                 | ACPI   | DELL      | EVENT | KBBLLV3 | keyboard backlight at level 3
                 | ACPI   | DELL      | EVENT | KBBLLV4 | keyboard backlight at level 4
\<Fn> + \<F5>    | KBD    | KBDMXE    | KEY   | TPDTOGL | switch the touchpad on or off
\<Fn> + \<F8>    | KBD    | KBDMXE    | KEY   | DSPSELN | select next display configuration
\<WIN> + P       | KBD    | KBDMXE    | KEY   | DSPSELN | select next display configuration
\<Fn> + \<F10>   | KBD    | KBDMXE    | KEY   | BACK    | select previous track
\<Fn> + \<F11>   | KBD    | KBDMXE    | KEY   | PLYTOGL | play or pause the current track
\<Fn> + \<F12>   | KBD    | KBDMXE    | KEY   | FORWARD | select next track
\<VOL MUTE>      | KBD    | KBDMXE    | KEY   | VOLMUTE | mute the volume
\<VOL UP>        | KBD    | KBDMXE    | KEY   | VOLUP   | increase the volume
\<VOL DOWN>      | KBD    | KBDMXE    | KEY   | VOLDOWN | decrease the volume

Note that there are keys that do not have a description. They
apparently do not have a predefined meaning. I use some of them to
blank the screen or switch the wifi off.

Also there are the notifications about the state of the keyboard
backlight brightness. An implementation of an OSD display might
use these, for example.
