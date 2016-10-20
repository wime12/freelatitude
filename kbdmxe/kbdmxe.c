/*
 * kbdmxe.c
 */

/*-
 * Copyright (c) 2005 Maksim Yevmenkin <m_evmenkin@yahoo.com>,
 *               2016 Wilfried Meindl <wilfried.meindl@gmail.com>
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: kbdmxe.c,v 1.3 2016/10/14 18:50:54 wilfried Exp wilfried $
 * $FreeBSD$
 */

#include "opt_compat.h"
#include "opt_kbd.h"
#include "opt_kbdmxe.h"

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/consio.h>
#include <sys/fcntl.h>
#include <sys/kbio.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/selinfo.h>
#include <sys/systm.h>
#include <sys/taskqueue.h>
#include <sys/uio.h>
#include <dev/kbd/kbdreg.h>

/* the initial key map, accent map and fkey strings */
#ifdef KBDMXE_DFLT_KEYMAP
#define KBD_DFLT_KEYMAP
#include "kbdmxemap.h"
#endif

#include <dev/kbd/kbdtables.h>

#define KEYBOARD_NAME	"kbdmxe"

MALLOC_DECLARE(M_KBDMXE);
MALLOC_DEFINE(M_KBDMXE, KEYBOARD_NAME, "Keyboard multiplexor with devd notification");

/*****************************************************************************
 *****************************************************************************
 **                             Keyboard state
 *****************************************************************************
 *****************************************************************************/

#define	KBDMXE_Q_SIZE	512	/* input queue size */

/*
 * XXX
 * For now rely on Giant mutex to protect our data structures.
 * Just like the rest of keyboard drivers and syscons(4) do.
 * Note that callout is initialized as not MP-safe to make sure
 * Giant is held.
 */

#if 0 /* not yet */
#define KBDMXE_LOCK_DECL_GLOBAL \
	struct mtx ks_lock
#define KBDMXE_LOCK_INIT(s) \
	mtx_init(&(s)->ks_lock, "kbdmxe", NULL, MTX_DEF|MTX_RECURSE)
#define KBDMXE_LOCK_DESTROY(s) \
	mtx_destroy(&(s)->ks_lock)
#define KBDMXE_LOCK(s) \
	mtx_lock(&(s)->ks_lock)
#define KBDMXE_UNLOCK(s) \
	mtx_unlock(&(s)->ks_lock)
#define KBDMXE_LOCK_ASSERT(s, w) \
	mtx_assert(&(s)->ks_lock, (w))
#define KBDMXE_SLEEP(s, f, d, t) \
	msleep(&(s)->f, &(s)->ks_lock, PCATCH | (PZERO + 1), (d), (t))
#define KBDMXE_CALLOUT_INIT(s) \
	callout_init_mtx(&(s)->ks_timo, &(s)->ks_lock, 0)
#define KBDMXE_QUEUE_INTR(s) \
	taskqueue_enqueue(taskqueue_swi_giant, &(s)->ks_task)
#else
#define KBDMXE_LOCK_DECL_GLOBAL

#define KBDMXE_LOCK_INIT(s)

#define KBDMXE_LOCK_DESTROY(s)

#define KBDMXE_LOCK(s)

#define KBDMXE_UNLOCK(s)

#define KBDMXE_LOCK_ASSERT(s, w)

#define KBDMXE_SLEEP(s, f, d, t) \
	tsleep(&(s)->f, PCATCH | (PZERO + 1), (d), (t))
#define KBDMXE_CALLOUT_INIT(s) \
	callout_init(&(s)->ks_timo, 0)
#define KBDMXE_QUEUE_INTR(s) \
	taskqueue_enqueue(taskqueue_swi_giant, &(s)->ks_task)
#endif /* not yet */

/*
 * kbdmxe keyboard
 */
struct kbdmxe_kbd
{
	keyboard_t		*kbd;	/* keyboard */
	SLIST_ENTRY(kbdmxe_kbd)	 next;	/* link to next */
};

typedef struct kbdmxe_kbd	kbdmxe_kbd_t;

/*
 * kbdmxe state
 */
struct kbdmxe_state
{
	char			 ks_inq[KBDMXE_Q_SIZE]; /* input chars queue */
	unsigned int		 ks_inq_start;
	unsigned int		 ks_inq_length;
	struct task		 ks_task;	/* interrupt task */
	struct callout		 ks_timo;	/* timeout handler */
#define TICKS			(hz)		/* rate */

	int			 ks_flags;	/* flags */
#define COMPOSE			(1 << 0)	/* compose char flag */ 
#define POLLING			(1 << 1)	/* polling */
#define TASK			(1 << 2)	/* interrupt task queued */

	int			 ks_mode;	/* K_XLATE, K_RAW, K_CODE */
	int			 ks_state;	/* state */
	int			 ks_accents;	/* accent key index (> 0) */
	u_int			 ks_composed_char; /* composed char code */
	u_char			 ks_prefix;	/* AT scan code prefix */
	u_char			 ks_fn_prefix;  /* scan code prefix for notification */

	SLIST_HEAD(, kbdmxe_kbd) ks_kbds;	/* keyboards */

	KBDMXE_LOCK_DECL_GLOBAL;
};

typedef struct kbdmxe_state	kbdmxe_state_t;

/*****************************************************************************
 *****************************************************************************
 **                             Helper functions
 *****************************************************************************
 *****************************************************************************/

static task_fn_t		kbdmxe_kbd_intr;
static timeout_t		kbdmxe_kbd_intr_timo;
static kbd_callback_func_t	kbdmxe_kbd_event;

static void
kbdmxe_kbd_putc(kbdmxe_state_t *state, char c)
{
	unsigned int p;

	if (state->ks_inq_length == KBDMXE_Q_SIZE)
		return;

	p = (state->ks_inq_start + state->ks_inq_length) % KBDMXE_Q_SIZE;
	state->ks_inq[p] = c;
	state->ks_inq_length++;
}

static int
kbdmxe_kbd_getc(kbdmxe_state_t *state)
{
	unsigned char c;

	if (state->ks_inq_length == 0)
		return (-1);

	c = state->ks_inq[state->ks_inq_start];
	state->ks_inq_start = (state->ks_inq_start + 1) % KBDMXE_Q_SIZE;
	state->ks_inq_length--;

	return (c);
}

/*
 * Interrupt handler task
 */
void
kbdmxe_kbd_intr(void *xkbd, int pending)
{
	keyboard_t	*kbd = (keyboard_t *) xkbd;
	kbdmxe_state_t	*state = (kbdmxe_state_t *) kbd->kb_data;

	kbdd_intr(kbd, NULL);

	KBDMXE_LOCK(state);

	state->ks_flags &= ~TASK;
	wakeup(&state->ks_task);

	KBDMXE_UNLOCK(state);
}

/*
 * Schedule interrupt handler on timeout. Called with locked state.
 */
void
kbdmxe_kbd_intr_timo(void *xstate)
{
	kbdmxe_state_t	*state = (kbdmxe_state_t *) xstate;

	KBDMXE_LOCK_ASSERT(state, MA_OWNED);

	if (callout_pending(&state->ks_timo))
		return; /* callout was reset */

	if (!callout_active(&state->ks_timo))
		return; /* callout was stopped */

	callout_deactivate(&state->ks_timo);

	/* queue interrupt task if needed */
	if (state->ks_inq_length > 0 && !(state->ks_flags & TASK) &&
	    KBDMXE_QUEUE_INTR(state) == 0)
		state->ks_flags |= TASK;

	/* re-schedule timeout */
	callout_reset(&state->ks_timo, TICKS, kbdmxe_kbd_intr_timo, state);
}

/*
 * Process event from one of our keyboards
 */
static int
kbdmxe_kbd_event(keyboard_t *kbd, int event, void *arg)
{
	kbdmxe_state_t	*state = (kbdmxe_state_t *) arg;

	switch (event) {
	case KBDIO_KEYINPUT: {
		int	c;

		KBDMXE_LOCK(state);

		/*
		 * Read all chars from the keyboard
		 *
		 * Turns out that atkbd(4) check_char() method may return
		 * "true" while read_char() method returns NOKEY. If this
		 * happens we could stuck in the loop below. Avoid this
		 * by breaking out of the loop if read_char() method returns
		 * NOKEY.
		 */

		while (kbdd_check_char(kbd)) {
			c = kbdd_read_char(kbd, 0);
			if (c == NOKEY)
				break;
			if (c == ERRKEY)
				continue; /* XXX ring bell */
			if (!KBD_IS_BUSY(kbd))
				continue; /* not open - discard the input */

			kbdmxe_kbd_putc(state, c);
		}

		/* queue interrupt task if needed */
		if (state->ks_inq_length > 0 && !(state->ks_flags & TASK) &&
		    KBDMXE_QUEUE_INTR(state) == 0)
			state->ks_flags |= TASK;

		KBDMXE_UNLOCK(state);
		} break;

	case KBDIO_UNLOADING: {
		kbdmxe_kbd_t	*k;

		KBDMXE_LOCK(state);

		SLIST_FOREACH(k, &state->ks_kbds, next)
			if (k->kbd == kbd)
				break;

		if (k != NULL) {
			kbd_release(k->kbd, &k->kbd);
			SLIST_REMOVE(&state->ks_kbds, k, kbdmxe_kbd, next);

			k->kbd = NULL;

			free(k, M_KBDMXE);
		}

		KBDMXE_UNLOCK(state);
		} break;

	default:
		return (EINVAL);
		/* NOT REACHED */
	}

	return (0);
}

/****************************************************************************
 ****************************************************************************
 **                              Keyboard driver
 ****************************************************************************
 ****************************************************************************/

static int		kbdmxe_configure(int flags);
static kbd_probe_t	kbdmxe_probe;
static kbd_init_t	kbdmxe_init;
static kbd_term_t	kbdmxe_term;
static kbd_intr_t	kbdmxe_intr;
static kbd_test_if_t	kbdmxe_test_if;
static kbd_enable_t	kbdmxe_enable;
static kbd_disable_t	kbdmxe_disable;
static kbd_read_t	kbdmxe_read;
static kbd_check_t	kbdmxe_check;
static void             kbdmxe_notify(char *);
static kbd_read_char_t	kbdmxe_read_char;
static kbd_check_char_t	kbdmxe_check_char;
static kbd_ioctl_t	kbdmxe_ioctl;
static kbd_lock_t	kbdmxe_lock;
static void		kbdmxe_clear_state_locked(kbdmxe_state_t *state);
static kbd_clear_state_t kbdmxe_clear_state;
static kbd_get_state_t	kbdmxe_get_state;
static kbd_set_state_t	kbdmxe_set_state;
static kbd_poll_mode_t	kbdmxe_poll;

static keyboard_switch_t kbdmxesw = {
	.probe =	kbdmxe_probe,
	.init =		kbdmxe_init,
	.term =		kbdmxe_term,
	.intr =		kbdmxe_intr,
	.test_if =	kbdmxe_test_if,
	.enable =	kbdmxe_enable,
	.disable =	kbdmxe_disable,
	.read =		kbdmxe_read,
	.check =	kbdmxe_check,
	.read_char =	kbdmxe_read_char,
	.check_char =	kbdmxe_check_char,
	.ioctl =	kbdmxe_ioctl,
	.lock =		kbdmxe_lock,
	.clear_state =	kbdmxe_clear_state,
	.get_state =	kbdmxe_get_state,
	.set_state =	kbdmxe_set_state,
	.get_fkeystr =	genkbd_get_fkeystr,
	.poll =		kbdmxe_poll,
	.diag =		genkbd_diag,
};

/*
 * Return the number of found keyboards
 */
static int
kbdmxe_configure(int flags)
{
	return (1);
}

/*
 * Detect a keyboard
 */
static int
kbdmxe_probe(int unit, void *arg, int flags)
{
	if (resource_disabled(KEYBOARD_NAME, unit))
		return (ENXIO);

	return (0);
}

/*
 * Reset and initialize the keyboard (stolen from atkbd.c)
 */
static int
kbdmxe_init(int unit, keyboard_t **kbdp, void *arg, int flags)
{
	keyboard_t	*kbd = NULL;
	kbdmxe_state_t	*state = NULL;
	keymap_t	*keymap = NULL;
        accentmap_t	*accmap = NULL;
        fkeytab_t	*fkeymap = NULL;
	int		 error, needfree, fkeymap_size, delay[2];

	if (*kbdp == NULL) {
		*kbdp = kbd = malloc(sizeof(*kbd), M_KBDMXE, M_NOWAIT | M_ZERO);
		state = malloc(sizeof(*state), M_KBDMXE, M_NOWAIT | M_ZERO);
		keymap = malloc(sizeof(key_map), M_KBDMXE, M_NOWAIT);
		accmap = malloc(sizeof(accent_map), M_KBDMXE, M_NOWAIT);
		fkeymap = malloc(sizeof(fkey_tab), M_KBDMXE, M_NOWAIT);
		fkeymap_size = sizeof(fkey_tab)/sizeof(fkey_tab[0]);
		needfree = 1;

		if ((kbd == NULL) || (state == NULL) || (keymap == NULL) ||
		    (accmap == NULL) || (fkeymap == NULL)) {
			error = ENOMEM;
			goto bad;
		}

		KBDMXE_LOCK_INIT(state);
		TASK_INIT(&state->ks_task, 0, kbdmxe_kbd_intr, (void *) kbd);
		KBDMXE_CALLOUT_INIT(state);
		SLIST_INIT(&state->ks_kbds);
	} else if (KBD_IS_INITIALIZED(*kbdp) && KBD_IS_CONFIGURED(*kbdp)) {
		return (0);
	} else {
		kbd = *kbdp;
		state = (kbdmxe_state_t *) kbd->kb_data;
		keymap = kbd->kb_keymap;
		accmap = kbd->kb_accentmap;
		fkeymap = kbd->kb_fkeytab;
		fkeymap_size = kbd->kb_fkeytab_size;
		needfree = 0;
	}

	if (!KBD_IS_PROBED(kbd)) {
		/* XXX assume 101/102 keys keyboard */
		kbd_init_struct(kbd, KEYBOARD_NAME, KB_101, unit, flags, 0, 0);
		bcopy(&key_map, keymap, sizeof(key_map));
		bcopy(&accent_map, accmap, sizeof(accent_map));
		bcopy(fkey_tab, fkeymap,
			imin(fkeymap_size*sizeof(fkeymap[0]), sizeof(fkey_tab)));
		kbd_set_maps(kbd, keymap, accmap, fkeymap, fkeymap_size);
		kbd->kb_data = (void *)state;
	
		KBD_FOUND_DEVICE(kbd);
		KBD_PROBE_DONE(kbd);

		KBDMXE_LOCK(state);
		kbdmxe_clear_state_locked(state);
		state->ks_mode = K_XLATE;
		KBDMXE_UNLOCK(state);
	}

	if (!KBD_IS_INITIALIZED(kbd) && !(flags & KB_CONF_PROBE_ONLY)) {
		kbd->kb_config = flags & ~KB_CONF_PROBE_ONLY;

		kbdmxe_ioctl(kbd, KDSETLED, (caddr_t)&state->ks_state);

		delay[0] = kbd->kb_delay1;
		delay[1] = kbd->kb_delay2;
		kbdmxe_ioctl(kbd, KDSETREPEAT, (caddr_t)delay);

		KBD_INIT_DONE(kbd);
	}

	if (!KBD_IS_CONFIGURED(kbd)) {
		if (kbd_register(kbd) < 0) {
			error = ENXIO;
			goto bad;
		}

		KBD_CONFIG_DONE(kbd);

		KBDMXE_LOCK(state);
		callout_reset(&state->ks_timo, TICKS, kbdmxe_kbd_intr_timo, state);
		KBDMXE_UNLOCK(state);
	}

	return (0);
bad:
	if (needfree) {
		if (state != NULL)
			free(state, M_KBDMXE);
		if (keymap != NULL)
			free(keymap, M_KBDMXE);
		if (accmap != NULL)
			free(accmap, M_KBDMXE);
		if (fkeymap != NULL)
			free(fkeymap, M_KBDMXE);
		if (kbd != NULL) {
			free(kbd, M_KBDMXE);
			*kbdp = NULL;	/* insure ref doesn't leak to caller */
		}
	}

	return (error);
}

/*
 * Finish using this keyboard
 */
static int
kbdmxe_term(keyboard_t *kbd)
{
	kbdmxe_state_t	*state = (kbdmxe_state_t *) kbd->kb_data;
	kbdmxe_kbd_t	*k;

	KBDMXE_LOCK(state);

	/* kill callout */
	callout_stop(&state->ks_timo);

	/* wait for interrupt task */
	while (state->ks_flags & TASK)
		KBDMXE_SLEEP(state, ks_task, "kbdmxec", 0);

	/* release all keyboards from the mux */
	while ((k = SLIST_FIRST(&state->ks_kbds)) != NULL) {
		kbd_release(k->kbd, &k->kbd);
		SLIST_REMOVE_HEAD(&state->ks_kbds, next);

		k->kbd = NULL;

		free(k, M_KBDMXE);
	}

	KBDMXE_UNLOCK(state);

	kbd_unregister(kbd);

	KBDMXE_LOCK_DESTROY(state);
	bzero(state, sizeof(*state));
	free(state, M_KBDMXE);

	free(kbd->kb_keymap, M_KBDMXE);
	free(kbd->kb_accentmap, M_KBDMXE);
	free(kbd->kb_fkeytab, M_KBDMXE);
	free(kbd, M_KBDMXE);

	return (0);
}

/*
 * Keyboard interrupt routine
 */
static int
kbdmxe_intr(keyboard_t *kbd, void *arg)
{
	int	c;

	if (KBD_IS_ACTIVE(kbd) && KBD_IS_BUSY(kbd)) {
		/* let the callback function to process the input */
		(*kbd->kb_callback.kc_func)(kbd, KBDIO_KEYINPUT,
					    kbd->kb_callback.kc_arg);
	} else {
		/* read and discard the input; no one is waiting for input */
		do {
			c = kbdmxe_read_char(kbd, FALSE);
		} while (c != NOKEY);
	}

	return (0);
}

/*
 * Test the interface to the device
 */
static int
kbdmxe_test_if(keyboard_t *kbd)
{
	return (0);
}

/* 
 * Enable the access to the device; until this function is called,
 * the client cannot read from the keyboard.
 */
static int
kbdmxe_enable(keyboard_t *kbd)
{
	KBD_ACTIVATE(kbd);
	return (0);
}

/*
 * Disallow the access to the device
 */
static int
kbdmxe_disable(keyboard_t *kbd)
{
	KBD_DEACTIVATE(kbd);
	return (0);
}

/*
 * Read one byte from the keyboard if it's allowed
 */
static int
kbdmxe_read(keyboard_t *kbd, int wait)
{
	kbdmxe_state_t	*state = (kbdmxe_state_t *) kbd->kb_data;
	int		 c;

	KBDMXE_LOCK(state);
	c = kbdmxe_kbd_getc(state);
	KBDMXE_UNLOCK(state);

	if (c != -1)
		kbd->kb_count ++;

	return (KBD_IS_ACTIVE(kbd)? c : -1);
}

/*
 * Check if data is waiting
 */
static int
kbdmxe_check(keyboard_t *kbd)
{
	kbdmxe_state_t	*state = (kbdmxe_state_t *) kbd->kb_data;
	int		 ready;

	if (!KBD_IS_ACTIVE(kbd))
		return (FALSE);

	KBDMXE_LOCK(state);
	ready = (state->ks_inq_length > 0) ? TRUE : FALSE;
	KBDMXE_UNLOCK(state);

	return (ready);
}

void
kbdmxe_notify(char *data)
{
	char buf[16];
	snprintf(buf, sizeof(buf), "notify=%s", data);
	devctl_notify("KBD", "KBDMXE", "KEY", buf);
}

/*
 * Read char from the keyboard (stolen from atkbd.c)
 */
static u_int
kbdmxe_read_char(keyboard_t *kbd, int wait)
{
	kbdmxe_state_t	*state = (kbdmxe_state_t *) kbd->kb_data;
	u_int		 action;
	int		 scancode, keycode;

	KBDMXE_LOCK(state);

next_code:

	/* do we have a composed char to return? */
	if (!(state->ks_flags & COMPOSE) && (state->ks_composed_char > 0)) {
		action = state->ks_composed_char;
		state->ks_composed_char = 0;
		if (action > UCHAR_MAX) {
			KBDMXE_UNLOCK(state);

			return (ERRKEY);
		}

		KBDMXE_UNLOCK(state);

		return (action);
	}

	/* see if there is something in the keyboard queue */
	scancode = kbdmxe_kbd_getc(state);
	if (scancode == -1) {
		if (state->ks_flags & POLLING) {
			kbdmxe_kbd_t	*k;

			SLIST_FOREACH(k, &state->ks_kbds, next) {
				while (kbdd_check_char(k->kbd)) {
					scancode = kbdd_read_char(k->kbd, 0);
					if (scancode == NOKEY)
						break;
					if (scancode == ERRKEY)
						continue;
					if (!KBD_IS_BUSY(k->kbd))
						continue; 

					kbdmxe_kbd_putc(state, scancode);
				}
			}

			if (state->ks_inq_length > 0)
				goto next_code;
		}

		KBDMXE_UNLOCK(state);
		return (NOKEY);
	}
	/* XXX FIXME: check for -1 if wait == 1! */

	kbd->kb_count ++;

	/* fn keys */
	switch (state->ks_fn_prefix) {
	case 0x00:
		switch(scancode) {
		case 0xE0:
			state->ks_fn_prefix = 0xE0;
		}
		break;
	case 0xE0:
		state->ks_fn_prefix = 0;
		switch(scancode) {
		case 0x20:
			kbdmxe_notify("VOLMUTE");
		  	break;
		case 0xAE:
		  	kbdmxe_notify("VOLDOWN");
		  	break;
		case 0xB0:
		  	kbdmxe_notify("VOLUP");
		  	break;
		case 0x1E:
		  	kbdmxe_notify("TPDTOGL");
		  	break;
		case 0x90:
		  	kbdmxe_notify("BACK");
		  	break;
		case 0x99:
		  	kbdmxe_notify("FORWARD");
		  	break;
		case 0xA2:
		  	kbdmxe_notify("PLYTOGL");
		  	break;
		case 0x5B:
		  	state->ks_fn_prefix = 0xFF;
		  	break;
		}
		break;
	case 0xFF:
		switch(scancode) {
		case 0x19:
		  	kbdmxe_notify("DSPSELN");
		  	break;
		case 0xE0:
			state->ks_fn_prefix = 0xE0;
			break;
		}
		break;
	}

	/* return the byte as is for the K_RAW mode */
	if (state->ks_mode == K_RAW) {
		KBDMXE_UNLOCK(state);
		return (scancode);
	}

	/* translate the scan code into a keycode */
	keycode = scancode & 0x7F;
	switch (state->ks_prefix) {
	case 0x00:	/* normal scancode */
		switch(scancode) {
		case 0xB8:	/* left alt (compose key) released */
			if (state->ks_flags & COMPOSE) {
				state->ks_flags &= ~COMPOSE;
				if (state->ks_composed_char > UCHAR_MAX)
					state->ks_composed_char = 0;
			}
			break;
		case 0x38:	/* left alt (compose key) pressed */
			if (!(state->ks_flags & COMPOSE)) {
				state->ks_flags |= COMPOSE;
				state->ks_composed_char = 0;
			}
			break;
		case 0xE0:
		case 0xE1:
			state->ks_prefix = scancode;
			goto next_code;
		}
		break;
	case 0xE0:      /* 0xE0 prefix */
		state->ks_prefix = 0;
		switch (keycode) {
		case 0x1C:	/* right enter key */
			keycode = 0x59;
			break;
		case 0x1D:	/* right ctrl key */
			keycode = 0x5A;
			break;
		case 0x35:	/* keypad divide key */
			keycode = 0x5B;
			break;
		case 0x37:	/* print scrn key */
			keycode = 0x5C;
			break;
		case 0x38:	/* right alt key (alt gr) */
			keycode = 0x5D;
			break;
		case 0x46:	/* ctrl-pause/break on AT 101 (see below) */
			keycode = 0x68;
			break;
		case 0x47:	/* grey home key */
			keycode = 0x5E;
			break;
		case 0x48:	/* grey up arrow key */
			keycode = 0x5F;
			break;
		case 0x49:	/* grey page up key */
			keycode = 0x60;
			break;
		case 0x4B:	/* grey left arrow key */
			keycode = 0x61;
			break;
		case 0x4D:	/* grey right arrow key */
			keycode = 0x62;
			break;
		case 0x4F:	/* grey end key */
			keycode = 0x63;
			break;
		case 0x50:	/* grey down arrow key */
			keycode = 0x64;
			break;
		case 0x51:	/* grey page down key */
			keycode = 0x65;
			break;
		case 0x52:	/* grey insert key */
			keycode = 0x66;
			break;
		case 0x53:	/* grey delete key */
			keycode = 0x67;
			break;
		/* the following 3 are only used on the MS "Natural" keyboard */
		case 0x5b:	/* left Window key */
			keycode = 0x69;
			break;
		case 0x5c:	/* right Window key */
			keycode = 0x6a;
			break;
		case 0x5d:	/* menu key */
			keycode = 0x6b;
			break;
		case 0x5e:	/* power key */
			keycode = 0x6d;
			break;
		case 0x5f:	/* sleep key */
			keycode = 0x6e;
			break;
		case 0x63:	/* wake key */
			keycode = 0x6f;
			break;
		case 0x64:	/* [JP106USB] backslash, underscore */
			keycode = 0x73;
			break;
		default:	/* ignore everything else */
			goto next_code;
		}
		break;
	case 0xE1:	/* 0xE1 prefix */
		/* 
		 * The pause/break key on the 101 keyboard produces:
		 * E1-1D-45 E1-9D-C5
		 * Ctrl-pause/break produces:
		 * E0-46 E0-C6 (See above.)
		 */
		state->ks_prefix = 0;
		if (keycode == 0x1D)
			state->ks_prefix = 0x1D;
		goto next_code;
		/* NOT REACHED */
	case 0x1D:	/* pause / break */
		state->ks_prefix = 0;
		if (keycode != 0x45)
			goto next_code;
		keycode = 0x68;
		break;
	}

	/* XXX assume 101/102 keys AT keyboard */
	switch (keycode) {
	case 0x5c:	/* print screen */
		if (state->ks_flags & ALTS)
			keycode = 0x54;	/* sysrq */
		break;
	case 0x68:	/* pause/break */
		if (state->ks_flags & CTLS)
			keycode = 0x6c;	/* break */
		break;
	}

	/* return the key code in the K_CODE mode */
	if (state->ks_mode == K_CODE) {
		KBDMXE_UNLOCK(state);
		return (keycode | (scancode & 0x80));
	}

	/* compose a character code */
	if (state->ks_flags & COMPOSE) {
		switch (keycode | (scancode & 0x80)) {
		/* key pressed, process it */
		case 0x47: case 0x48: case 0x49:	/* keypad 7,8,9 */
			state->ks_composed_char *= 10;
			state->ks_composed_char += keycode - 0x40;
			if (state->ks_composed_char > UCHAR_MAX) {
				KBDMXE_UNLOCK(state);
				return (ERRKEY);
			}
			goto next_code;
		case 0x4B: case 0x4C: case 0x4D:	/* keypad 4,5,6 */
			state->ks_composed_char *= 10;
			state->ks_composed_char += keycode - 0x47;
			if (state->ks_composed_char > UCHAR_MAX) {
				KBDMXE_UNLOCK(state);
				return (ERRKEY);
			}
			goto next_code;
		case 0x4F: case 0x50: case 0x51:	/* keypad 1,2,3 */
			state->ks_composed_char *= 10;
			state->ks_composed_char += keycode - 0x4E;
			if (state->ks_composed_char > UCHAR_MAX) {
				KBDMXE_UNLOCK(state);
				return (ERRKEY);
			}
			goto next_code;
		case 0x52:	/* keypad 0 */
			state->ks_composed_char *= 10;
			if (state->ks_composed_char > UCHAR_MAX) {
				KBDMXE_UNLOCK(state);
				return (ERRKEY);
			}
			goto next_code;

		/* key released, no interest here */
		case 0xC7: case 0xC8: case 0xC9:	/* keypad 7,8,9 */
		case 0xCB: case 0xCC: case 0xCD:	/* keypad 4,5,6 */
		case 0xCF: case 0xD0: case 0xD1:	/* keypad 1,2,3 */
		case 0xD2:				/* keypad 0 */
			goto next_code;

		case 0x38:				/* left alt key */
			break;

		default:
			if (state->ks_composed_char > 0) {
				state->ks_flags &= ~COMPOSE;
				state->ks_composed_char = 0;
				KBDMXE_UNLOCK(state);
				return (ERRKEY);
			}
			break;
		}
	}

	/* keycode to key action */
	action = genkbd_keyaction(kbd, keycode, scancode & 0x80,
			&state->ks_state, &state->ks_accents);
	if (action == NOKEY)
		goto next_code;

	KBDMXE_UNLOCK(state);

	return (action);
}

/*
 * Check if char is waiting
 */
static int
kbdmxe_check_char(keyboard_t *kbd)
{
	kbdmxe_state_t	*state = (kbdmxe_state_t *) kbd->kb_data;
	int		 ready;

	if (!KBD_IS_ACTIVE(kbd))
		return (FALSE);

	KBDMXE_LOCK(state);

	if (!(state->ks_flags & COMPOSE) && (state->ks_composed_char != 0))
		ready = TRUE;
	else
		ready = (state->ks_inq_length > 0) ? TRUE : FALSE;

	KBDMXE_UNLOCK(state);

	return (ready);
}

/*
 * Keyboard ioctl's
 */
static int
kbdmxe_ioctl(keyboard_t *kbd, u_long cmd, caddr_t arg)
{
	static int	 delays[] = {
		250, 500, 750, 1000
	};

	static int	 rates[]  =  {
		34,  38,  42,  46,  50,   55,  59,  63,
		68,  76,  84,  92,  100, 110, 118, 126,
		136, 152, 168, 184, 200, 220, 236, 252,
		272, 304, 336, 368, 400, 440, 472, 504
	};

	kbdmxe_state_t	*state = (kbdmxe_state_t *) kbd->kb_data;
	kbdmxe_kbd_t	*k;
	keyboard_info_t	*ki;
	int		 error = 0, mode;
#ifdef COMPAT_FREEBSD6
	int		 ival;
#endif

	if (state == NULL)
		return (ENXIO);

	switch (cmd) {
	case KBADDKBD: /* add keyboard to the mux */
		ki = (keyboard_info_t *) arg;

		if (ki == NULL || ki->kb_unit < 0 || ki->kb_name[0] == '\0' ||
		    strcmp(ki->kb_name, "*") == 0)
			return (EINVAL); /* bad input */

		KBDMXE_LOCK(state);

		SLIST_FOREACH(k, &state->ks_kbds, next)
			if (k->kbd->kb_unit == ki->kb_unit &&
			    strcmp(k->kbd->kb_name, ki->kb_name) == 0)
				break;

		if (k != NULL) {
			KBDMXE_UNLOCK(state);

			return (0); /* keyboard already in the mux */
		}

		k = malloc(sizeof(*k), M_KBDMXE, M_NOWAIT | M_ZERO);
		if (k == NULL) {
			KBDMXE_UNLOCK(state);

			return (ENOMEM); /* out of memory */
		}

		k->kbd = kbd_get_keyboard(
				kbd_allocate(
					ki->kb_name,
					ki->kb_unit,
					(void *) &k->kbd,
					kbdmxe_kbd_event, (void *) state));
		if (k->kbd == NULL) {
			KBDMXE_UNLOCK(state);
			free(k, M_KBDMXE);

			return (EINVAL); /* bad keyboard */
		}

		kbdd_enable(k->kbd);
		kbdd_clear_state(k->kbd);

		/* set K_RAW mode on slave keyboard */
		mode = K_RAW;
		error = kbdd_ioctl(k->kbd, KDSKBMODE, (caddr_t)&mode);
		if (error == 0) {
			/* set lock keys state on slave keyboard */
			mode = state->ks_state & LOCK_MASK;
			error = kbdd_ioctl(k->kbd, KDSKBSTATE, (caddr_t)&mode);
		}

		if (error != 0) {
			KBDMXE_UNLOCK(state);

			kbd_release(k->kbd, &k->kbd);
			k->kbd = NULL;

			free(k, M_KBDMXE);

			return (error); /* could not set mode */
		}

		SLIST_INSERT_HEAD(&state->ks_kbds, k, next);

		KBDMXE_UNLOCK(state);
		break;

	case KBRELKBD: /* release keyboard from the mux */
		ki = (keyboard_info_t *) arg;

		if (ki == NULL || ki->kb_unit < 0 || ki->kb_name[0] == '\0' ||
		    strcmp(ki->kb_name, "*") == 0)
			return (EINVAL); /* bad input */

		KBDMXE_LOCK(state);

		SLIST_FOREACH(k, &state->ks_kbds, next)
			if (k->kbd->kb_unit == ki->kb_unit &&
			    strcmp(k->kbd->kb_name, ki->kb_name) == 0)
				break;

		if (k != NULL) {
			error = kbd_release(k->kbd, &k->kbd);
			if (error == 0) {
				SLIST_REMOVE(&state->ks_kbds, k, kbdmxe_kbd, next);

				k->kbd = NULL;

				free(k, M_KBDMXE);
			}
		} else
			error = ENXIO; /* keyboard is not in the mux */

		KBDMXE_UNLOCK(state);
		break;

	case KDGKBMODE: /* get kyboard mode */
		KBDMXE_LOCK(state);
		*(int *)arg = state->ks_mode;
		KBDMXE_UNLOCK(state);
		break;

#ifdef COMPAT_FREEBSD6
	case _IO('K', 7):
		ival = IOCPARM_IVAL(arg);
		arg = (caddr_t)&ival;
		/* FALLTHROUGH */
#endif
	case KDSKBMODE: /* set keyboard mode */
		KBDMXE_LOCK(state);

		switch (*(int *)arg) {
		case K_XLATE:
			if (state->ks_mode != K_XLATE) {
				/* make lock key state and LED state match */
				state->ks_state &= ~LOCK_MASK;
				state->ks_state |= KBD_LED_VAL(kbd);
                        }
                        /* FALLTHROUGH */

		case K_RAW:
		case K_CODE:
			if (state->ks_mode != *(int *)arg) {
				kbdmxe_clear_state_locked(state);
				state->ks_mode = *(int *)arg;
			}
			break;

                default:
			error = EINVAL;
			break;
		}

		KBDMXE_UNLOCK(state);
		break;

	case KDGETLED: /* get keyboard LED */
		KBDMXE_LOCK(state);
		*(int *)arg = KBD_LED_VAL(kbd);
		KBDMXE_UNLOCK(state);
		break;

#ifdef COMPAT_FREEBSD6
	case _IO('K', 66):
		ival = IOCPARM_IVAL(arg);
		arg = (caddr_t)&ival;
		/* FALLTHROUGH */
#endif
	case KDSETLED: /* set keyboard LED */
		KBDMXE_LOCK(state);

		/* NOTE: lock key state in ks_state won't be changed */
		if (*(int *)arg & ~LOCK_MASK) {
			KBDMXE_UNLOCK(state);

			return (EINVAL);
		}

		KBD_LED_VAL(kbd) = *(int *)arg;

		/* KDSETLED on all slave keyboards */
		SLIST_FOREACH(k, &state->ks_kbds, next)
			(void)kbdd_ioctl(k->kbd, KDSETLED, arg);

		KBDMXE_UNLOCK(state);
		break;

	case KDGKBSTATE: /* get lock key state */
		KBDMXE_LOCK(state);
		*(int *)arg = state->ks_state & LOCK_MASK;
		KBDMXE_UNLOCK(state);
		break;

#ifdef COMPAT_FREEBSD6
	case _IO('K', 20):
		ival = IOCPARM_IVAL(arg);
		arg = (caddr_t)&ival;
		/* FALLTHROUGH */
#endif
	case KDSKBSTATE: /* set lock key state */
		KBDMXE_LOCK(state);

		if (*(int *)arg & ~LOCK_MASK) {
			KBDMXE_UNLOCK(state);

			return (EINVAL);
		}

		state->ks_state &= ~LOCK_MASK;
		state->ks_state |= *(int *)arg;

		/* KDSKBSTATE on all slave keyboards */
		SLIST_FOREACH(k, &state->ks_kbds, next)
			(void)kbdd_ioctl(k->kbd, KDSKBSTATE, arg);

		KBDMXE_UNLOCK(state);

		return (kbdmxe_ioctl(kbd, KDSETLED, arg));
		/* NOT REACHED */

#ifdef COMPAT_FREEBSD6
	case _IO('K', 67):
		cmd = KDSETRAD;
		ival = IOCPARM_IVAL(arg);
		arg = (caddr_t)&ival;
		/* FALLTHROUGH */
#endif
	case KDSETREPEAT: /* set keyboard repeat rate (new interface) */
	case KDSETRAD: /* set keyboard repeat rate (old interface) */
		KBDMXE_LOCK(state);

		if (cmd == KDSETREPEAT) {
			int	i;

			/* lookup delay */
			for (i = sizeof(delays)/sizeof(delays[0]) - 1; i > 0; i --)
				if (((int *)arg)[0] >= delays[i])
					break;
			mode = i << 5;

			/* lookup rate */
			for (i = sizeof(rates)/sizeof(rates[0]) - 1; i > 0; i --)
				if (((int *)arg)[1] >= rates[i])
					break;
			mode |= i;
		} else
			mode = *(int *)arg;

		if (mode & ~0x7f) {
			KBDMXE_UNLOCK(state);

			return (EINVAL);
		}

		kbd->kb_delay1 = delays[(mode >> 5) & 3];
		kbd->kb_delay2 = rates[mode & 0x1f];

		/* perform command on all slave keyboards */
		SLIST_FOREACH(k, &state->ks_kbds, next)
			(void)kbdd_ioctl(k->kbd, cmd, arg);

		KBDMXE_UNLOCK(state);
		break;

	case PIO_KEYMAP:	/* set keyboard translation table */
	case OPIO_KEYMAP:	/* set keyboard translation table (compat) */
	case PIO_KEYMAPENT:	/* set keyboard translation table entry */
	case PIO_DEADKEYMAP:	/* set accent key translation table */
		KBDMXE_LOCK(state);
                state->ks_accents = 0;

		/* perform command on all slave keyboards */
		SLIST_FOREACH(k, &state->ks_kbds, next)
			(void)kbdd_ioctl(k->kbd, cmd, arg);

		KBDMXE_UNLOCK(state);
                /* FALLTHROUGH */

	default:
		error = genkbd_commonioctl(kbd, cmd, arg);
		break;
	}

	return (error);
}

/*
 * Lock the access to the keyboard
 */
static int
kbdmxe_lock(keyboard_t *kbd, int lock)
{
	return (1); /* XXX */
}

/*
 * Clear the internal state of the keyboard
 */
static void
kbdmxe_clear_state_locked(kbdmxe_state_t *state)
{
	KBDMXE_LOCK_ASSERT(state, MA_OWNED);

	state->ks_flags &= ~(COMPOSE|POLLING);
	state->ks_state &= LOCK_MASK;	/* preserve locking key state */
	state->ks_accents = 0;
	state->ks_composed_char = 0;
/*	state->ks_prefix = 0;		XXX */
	state->ks_inq_length = 0;
}

static void
kbdmxe_clear_state(keyboard_t *kbd)
{
	kbdmxe_state_t	*state = (kbdmxe_state_t *) kbd->kb_data;

	KBDMXE_LOCK(state);
	kbdmxe_clear_state_locked(state);
	KBDMXE_UNLOCK(state);
}

/*
 * Save the internal state
 */
static int
kbdmxe_get_state(keyboard_t *kbd, void *buf, size_t len)
{
	if (len == 0)
		return (sizeof(kbdmxe_state_t));
	if (len < sizeof(kbdmxe_state_t))
		return (-1);

	bcopy(kbd->kb_data, buf, sizeof(kbdmxe_state_t)); /* XXX locking? */

	return (0);
}

/*
 * Set the internal state
 */
static int
kbdmxe_set_state(keyboard_t *kbd, void *buf, size_t len)
{
	if (len < sizeof(kbdmxe_state_t))
		return (ENOMEM);

	bcopy(buf, kbd->kb_data, sizeof(kbdmxe_state_t)); /* XXX locking? */

	return (0);
}

/*
 * Set polling
 */
static int
kbdmxe_poll(keyboard_t *kbd, int on)
{
	kbdmxe_state_t	*state = (kbdmxe_state_t *) kbd->kb_data;
	kbdmxe_kbd_t	*k;

	KBDMXE_LOCK(state);

	if (on)
		state->ks_flags |= POLLING; 
	else
		state->ks_flags &= ~POLLING;

	/* set poll on slave keyboards */
	SLIST_FOREACH(k, &state->ks_kbds, next)
		kbdd_poll(k->kbd, on);

	KBDMXE_UNLOCK(state);

	return (0);
}

/*****************************************************************************
 *****************************************************************************
 **                                    Module 
 *****************************************************************************
 *****************************************************************************/

KEYBOARD_DRIVER(kbdmxe, kbdmxesw, kbdmxe_configure);

static int
kbdmxe_modevent(module_t mod, int type, void *data)
{
	keyboard_switch_t	*sw;
	keyboard_t		*kbd;
	int			 error;

	switch (type) {
	case MOD_LOAD:
		if ((error = kbd_add_driver(&kbdmxe_kbd_driver)) != 0)
			break;

		if ((sw = kbd_get_switch(KEYBOARD_NAME)) == NULL) {
			kbd_delete_driver(&kbdmxe_kbd_driver);
			error = ENXIO;
			break;
		}

		kbd = NULL;

		if ((error = (*sw->probe)(0, NULL, 0)) != 0 ||
		    (error = (*sw->init)(0, &kbd, NULL, 0)) != 0) {
			kbd_delete_driver(&kbdmxe_kbd_driver);
			break;
		}

#ifdef KBD_INSTALL_CDEV
		if ((error = kbd_attach(kbd)) != 0) {
			(*sw->term)(kbd);
			kbd_delete_driver(&kbdmxe_kbd_driver);
			break;
		}
#endif

		if ((error = (*sw->enable)(kbd)) != 0) {
			(*sw->disable)(kbd);
#ifdef KBD_INSTALL_CDEV
			kbd_detach(kbd);
#endif
			(*sw->term)(kbd);
			kbd_delete_driver(&kbdmxe_kbd_driver);
			break;
		}
		break;

	case MOD_UNLOAD:
		if ((sw = kbd_get_switch(KEYBOARD_NAME)) == NULL)
			panic("kbd_get_switch(" KEYBOARD_NAME ") == NULL");

		kbd = kbd_get_keyboard(kbd_find_keyboard(KEYBOARD_NAME, 0));
		if (kbd != NULL) {
			(*sw->disable)(kbd);
#ifdef KBD_INSTALL_CDEV
			kbd_detach(kbd);
#endif
			(*sw->term)(kbd);
			kbd_delete_driver(&kbdmxe_kbd_driver);
		}
		error = 0;
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

DEV_MODULE(kbdmxe, kbdmxe_modevent, NULL);

