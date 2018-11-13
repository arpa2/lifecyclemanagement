

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include <time.h>
#include <syslog.h>
#include <errno.h>


//TODO// Include pulleyback.h locally (for now)
#include "pulleyback.h"
#include "lifecycle.h"



/********** UTILITY FUNCTIONS **********/



/* Find the length of an identifier */
size_t idlen (char *idstr) {
	size_t rv = 0;
	while (idstr [rv] != '\0') {
		char c = idstr [rv++];
		if ((isalnum (c)) || (c == '-') || (c == '_')) {
			continue;
		} else {
			break;
		}
	}
	return rv;
}


/* Find the "type" of an event, usually '@' or '?' or '=' but possibly NUL.
 */
char find_type (char *next) {
	return next [idlen (next)];
}


/* Locally implement the non-standard function strchrnul() that is like
 * strchr() except that it will return a pointer to the NUL character
 * at the string's end when it finds no occurrence.
 */
char *strchrnul (char *s, int c) {
	while ((*s != '\0') && (*s != c)) {
		s++;
	}
	return s;
}


/* Compare a NUL-terminated ASCII string with a (ptr,len) memory region
 * that is also ASCII-compliant and lacks internal NUL characters.
 */
int strmemcmp (char *str, char *mem, size_t memlen) {
	int rv = strncmp (str, (char *) mem, memlen);
	if (rv == 0) {
		if (str [memlen] != '\0') {
			rv = -1;
		}
	}
	return rv;
}


/* Parse the pointer and length from a DER header.
 * Return success as true, failure as false.
 */
bool parse_der (uint8_t *der, char **ptr, size_t *len) {
	der++;
	if ((*der & 0x80) != 0x00) {
		int lenlen = (*der & 0x7f);
		if ((lenlen < 1) || (lenlen > 2)) {
			return false;
		}
		*len = der [0];
		if (lenlen == 2) {
			*len = ((*len) << 8) | der [1];
			*ptr = (char *) (der + 2);
		} else {
			*ptr = (char *) (der + 1);
		}
	} else {
		*len = *der;
		*ptr = (char *) (der + 1);
	}
	return true;
}


/********** ALLOCATION AND FREEING **********/



/* Allocate and init a new lifecycleState structure, for the given attribute.
 * Add it to the lifecycleObject structure.
 */
struct lcstate *new_lcstate (struct lcobject *lco, char *lcs, size_t lcslen) {
	struct lcstate *new = calloc (sizeof (struct lcstate) + lcslen, 1);
	if (new == NULL) {
		syslog (LOG_CRIT, "FATAL: Failed to allocate lcstate with %zd characters", lcslen);
		exit (1);
	}
	// trailing NUL from calloc() [allocated due to char[1] in struct)
	memcpy (new->txt_attr, lcs, lcslen);
	// cnt_missed was zeroed by calloc()
	char *dot = strstr (new->txt_attr, " . ");
	if (dot == NULL) {
		syslog (LOG_ERR, "Operational Flaw: lifecycleState without internal dot: \"%s\"", new->txt_attr);
		new->ofs_next = lcslen;
		new->typ_next = '\0';
	} else {
		new->ofs_next = 3 + dot - new->txt_attr;
		new->typ_next = find_type (dot + 3);
	}
	// tim_next is made "dirty" or 0 by calloc()
	// We shall first go through update_lcstate_events() anyway
	lco->tim_first = 0;
	new->lcs_next = lco->lcs_first;
	lco->lcs_first = new;
	return new;
}


/* Free a lifecycleState structure and set its reference to NULL.
 */
void free_lcstate (struct lcstate **lcs) {
	assert ((*lcs)->lcs_next == NULL);
	free (*lcs);
	*lcs = NULL;
}


/* Find a lifecycleState in a linked list with possible end marker.
 * The value to be found usually comes from DER, so it is given as
 * a memory (ptr,len) pair.
 * Return NULL when the exact string was not found.
 */
struct lcstate **find_lcstate_ptr (struct lcstate **first,
                                   struct lcstate *last_opt,
                                   char *mem, size_t memlen) {
	while ((*first) != last_opt) {
		if (0 == (strmemcmp ((*first)->txt_attr, mem, memlen))) {
			return first;
		}
		first = & (*first)->lcs_next;
	}
	return NULL;
}


/* Allocate and init a new lifecycleObject structure, for the given DN.
 */
struct lcobject *new_lcobject (char *dn, size_t dnlen) {
	struct lcobject *new = calloc (sizeof (struct lcobject) + dnlen, 1);
	if (new == NULL) {
		syslog (LOG_CRIT, "FATAL: Failed to allocate lcobject with %zd characters", dnlen);
		exit (1);
	}
	// trailing NUL from calloc() [allocated due to char[1] in struct)
	memcpy (new->txt_dn, dn, dnlen);
	// TODO: compute hsh_dn
	new->tim_first = ~ (time_t) 0;  // highest possible setting
	// lcs_first was set to NULL by calloc()
	// lco_next  was set to NULL by calloc()
	return new;
}


/* Free a lifecycleObject structure and set its reference to NULL.
 */
void free_lcobject (struct lcobject **lco) {
	assert ((*lco)->lco_next == NULL);
	struct lcstate *lcs;
	lcs = (*lco)->lcs_first;
	while (lcs != NULL) {
		struct lcstate *lcn = lcs->lcs_next;
		free_lcstate (&lcs);
		lcs = lcn;
	}
	free (*lco);
	*lco = NULL;
}


/* Find a lifecycleObject in a linked list.
 * The value to be found usually comes from DER, so it is given as
 * a memory (ptr,len) pair.
 * Return NULL when the exact string was not found.
 */
struct lcobject *find_lcobject (struct lcobject *first,
				char *mem, size_t memlen) {
	while (first != NULL) {
		if (0 == (strmemcmp (first->txt_dn, mem, memlen))) {
			return first;
		}
		first = first->lco_next;
	}
	return NULL;
}



/********** TIMER FUNCTIONS **********/



/* Mark the firing time in an lcobject as "dirty", that is,
 * as being in need of an update.
 */
void smudge_lcobject_firetiem (struct lcobject *lco) {
	lco->tim_first = 0;
}


/* Mark the firing time in an lcstate as "dirty", that is,
 * as being in need of an update.  This may also apply to the
 * lcobject, which oversees the various timers.
 */
void smudge_lcstate_firetime (struct lcstate *lcs, struct lcobject *lco) {
	if (lcs->tim_next != 0) {
		if (lcs->tim_next == lco->tim_first) {
			// We determined the lcobject's next fire time
			lco->tim_first = 0;
		}
		lcs->tim_next = 0;
	}
}


/* Test if the firing time in an lcstate is "dirty", that is,
 * needs an update.
 */
bool dirty_lcstate_firetime (struct lcstate *lcs) {
	return lcs->tim_next == 0;
}


/* Test if the firing time in an lcobject is "dirty", that is,
 * needs an update.
 */
bool dirty_lcobject_firetime (struct lcobject *lco) {
	return lco->tim_first == 0;
}


/* When the next event is '@' type, test when it may fire.
 */
time_t update_lcstate_firetime (struct lcstate *lcs) {
	time_t update = ~ (time_t) 0;
	if (lcs->typ_next != '@') {
		goto done;
	}
	char *timestr = strchr (lcs->txt_attr + lcs->ofs_next, '@');
	if (timestr == NULL) {
		goto done;
	}
	timestr++;
	if ((*timestr == ' ') || (*timestr == '\0')) {
		update = time (NULL);
		goto done;
	}
	unsigned long stamp = strtoul (timestr, &timestr, 10);
	if (stamp != (unsigned long) (time_t) stamp) {
		syslog (LOG_ERR, "Time out of bounds: %zd", stamp);
		goto done;
	}
	update = stamp;
done:
	lcs->tim_next = update;
	return update;
}


/* Recalculate values for a dirty object, and reset dirty status.
 *
 * This involves recalculation of the tim_first value, which signals
 * dirty status .
 */
void update_lcobject_firetime (struct lcobject *lco) {
	lco->tim_first = ~ (time_t) 0;
	struct lcstate *lcs = lco->lcs_first;
	while (lcs != NULL) {
		if (dirty_lcstate_firetime (lcs)) {
			update_lcstate_firetime (lcs);
		}
		assert (lcs->tim_next != 0);
		if (lcs->tim_next < lco->tim_first) {
			lco->tim_first = lcs->tim_next;
		}
		lcs = lcs->lcs_next;
	}
}



/********** EVENT EXCHANGE **********/



/* Advance one or more '?' events in a given lcstate.
 *
 * This MUST NOT be run while an LDAP transaction is in progress, as it
 * might temporarily remove an attribute.  We would be breaking atomicity
 * if we acted on a missing attribute.
 *
 * This change is idempotent.  Return whether something new was advanced.
 */
bool advance_lcstate_events (struct lcstate *lcs, struct lcobject *lco) {
	bool retval = false;
	bool didsth = true;
	while (didsth) {
		didsth = false;
		if (lcs->typ_next != '?') {
			return false;
		}
		char *src = lcs->txt_attr + lcs->ofs_next;
		size_t srclen = idlen (src);
		assert (src [srclen] == '@');
		// Search for the matching other
		struct lcstate *other = lco->lcs_first;
		while (other != NULL) {
			size_t lclen = idlen (lcs->txt_attr);
			if ((lclen == srclen) && (0 == strncmp (lcs->txt_attr, src, srclen))) {
				// Found the right "other", stop searching
				break;
			}
			other=other->lcs_next;
		}
		// We found the matching other, or it is NULL
		char *next = lcs->txt_attr + lcs->ofs_next;
		if (other == NULL) {
			syslog (LOG_WARNING, "No matching life cycle for %.*s, passing it silently", (int) srclen, src);
			didsth = true;
		} else {
			// We found the matching other, test it
			char *evt = src + srclen + 1;
			size_t evtlen = idlen (evt);
			char *trig = strchrnul (lcs->txt_attr, ' ');
			while (*trig == ' ') {
				trig++;
				if (trig >= next) {
					// Won't look into the future
					break;
				}
				size_t trglen = idlen (trig);
				if ((trglen == evtlen) && (0 == memcmp (trig ,evt, evtlen))) {
					// The event has occurred in the past
					didsth = true;
					break;
				}
				if (*trig != '.') {
					trig = strchrnul (trig, ' ');
				}
			}
		}
		// Now advance to the next event if we did something
		if (didsth) {
			next = strchrnul (next, ' ');
			if (*next == ' ') {
				next++;
			}
			lcs->ofs_next = next - lcs->txt_attr;
			smudge_lcstate_firetime (lcs, lco);
		}
		// Take note if we did something
		retval = retval || didsth;
	}
	return retval;
}


/* Advance all possible '?' events in a given lcobject.
 *
 * This MUST NOT be run while an LDAP transaction is in progress, as it
 * might temporarily remove an attribute.  We would be breaking atomicity
 * if we acted on a missing attribute.
 *
 * This change is idempotent.  Return whether something new was advanced.
 */
bool advance_lcobject_events (struct lcobject *lco) {
	bool retval = false;
	bool didsth = true;
	while (didsth) {
		didsth = false;
		struct lcstate *lcs = lco->lcs_first;
		while (lcs != NULL) {
			didsth = advance_lcstate_events (lcs, lco);
			lcs = lcs->lcs_next;
		}
		retval = retval || didsth;
	}
	return retval;
}


/* Explicitly fire a certain lcstate's events.  This is useful after a
 * timer has expired.  When this does indeed trigger events, it is also
 * desirable to go through other objects and try to advance those.
 *
 * This MUST NOT be run while an LDAP transaction is in progress, as it
 * might temporarily remove an attribute.  We would be breaking atomicity
 * if we acted on a missing attribute.
 *
 * This change is idempotent.  Return whether something new was advanced.
 */
#if 0
bool fire_lcstate_events (struct lcstate *lcs, struct lcobject *lco) {
	if (!advance_lcstate_events (lcs, lco)) {
		return false;
	}
	advance_lcobject_events (lco);
	return true;
}
#endif /* 0 */



/********** OVERALL PROCESSING **********/



/* The general course of action is always as follows:
 *
 *  1. Advance any events that can proceed
 *  2. Update timers, find the first @timer to fire
 *  3. Wait for the first @timer to occur
 *  4. Externally trigger the corresponding lcstate @timer
 *  5. Repeat with exponential fallback until lcstate is updated
 *  6. Fire the lcstate ?events, update object, goto 2.
 *
 * This tidy run of events is dirsupted by LDAP, so that step 6 need not
 * be taken care of here; LDAP changes to the lcstate would cause a restart.
 * Some clever caching of changes during LDAP transactions could be useful.
 */


/* When a backend instance is openened, it is given its own thread.
 * When the backend instance is closed, the thread is taken away.
 *
 * The context of each thread is its own lcenv.  It passes lines
 * to output drivers, multiple if need be -- LDAP can wait for us.
 * Output drivers may be assumed to run without cross-connections, so
 * we need not be afraid of deadlocks there either.
 * 
 * On a regular basis however, the thread releases its Mutex lock on
 * lcenv, and after grabbing it again it will start from scratch.
 * While the Mutex was held by LDAP, it may have added and deleted
 * lcobject and lcstate representations, as the environment sees fit.
 *
 * The Mutex in the lcenv is claimed during transaction start, and
 * released after transaction end, good or bad.
 *
 * #TODO# No LDAP and no output; how to handle the Mutex?
 */



/********** TRANSACTION SUPPORT **********/



/* Test if a transaction is active on the lcenv.
 */
bool txn_isactive (struct lcenv *lce) {
	return lce->env_txncycle != NULL;
}


/* Open a fresh transaction.
 *
 * #TODO# Await Mutex for exclusive access by transaction
 */
void txn_open (struct lcenv *lce) {
	assert (! txn_isactive (lce));
	lce->env_txncycle = lce;
	// Setup each lcobject for attribute changes
	struct lcobject *lco = lce->lco_first;
	while (lco != NULL) {
		assert (lco->lcs_toadd == NULL);
		assert (lco->lcs_todel == NULL);
		lco->lcs_toadd = lco->lcs_first;
		lco = lco->lco_next;
	}
}


/* Break a transaction.  This recovers old state and disables any
 * further activity.
 *
 * #TODO# Release Mutex claimed by transaction, no pthread_cond_signal()
 */
void txn_break (struct lcenv *lce) {
	assert (txn_isactive (lce));
	struct lcenv *txnext;
	while (txnext = lce->env_txncycle, txnext != NULL) {
		lce->env_txncycle = NULL;
		struct lcobject *lco = lce->lco_first;
		while (lco != NULL) {
			struct lcstate *lcs = lco->lcs_toadd;
			while (lcs != lco->lcs_first) {
				struct lcstate *next = lcs->lcs_next;
				free_lcstate (&lcs);
				lcs = next;
			}
			lco->lcs_toadd = NULL;
			lco->lcs_todel = NULL;
			lco = lco->lco_next;
		}
		lce = txnext;
	}
}



/* The current transaction is done.
 * Delete what was setup for deletion, add what was prepared.
 *
 * #TODO# Release Mutex claimed by transaction + pthread_cond_signal()
 */
void txn_done (struct lcenv *lce) {
	assert (txn_isactive (lce));
	struct lcenv *txnext;
	while (txnext = lce->env_txncycle, txnext != NULL) {
		lce->env_txncycle = NULL;
		struct lcobject **plco = & lce->lco_first;
		while (*plco != NULL) {
			struct lcobject *lco = *plco;
			struct lcstate **plcs = & lco->lcs_first;
			struct lcstate *next;
			while (next = *plcs, next != NULL) {
				free_lcstate (plcs);
				plcs = & next->lcs_next;
			}
			lco->lcs_first = lco->lcs_toadd;
			lco->lcs_toadd = NULL;
			if (lco->lcs_first == NULL) {
				// Empty object.  Cleanup and resample *plco
				*plco = lco->lco_next;
				free_lcobject (&lco);
			} else {
				// Proper object.  Continue to next *plco
				plco = & lco->lco_next;
			}
		}
		lce = txnext;
	}
}


/* Empty the current database (as part of a transaction).
 */
void txn_emptydata (struct lcenv *lce) {
	assert (txn_isactive (lce));
	struct lcobject *lco = lce->lco_first;
	while (lco != NULL) {
		lco->lcs_todel =
		lco->lcs_first = lco->lcs_toadd;
		lco = lco->lco_next;
	}
}



/********** PULLEY BACKEND **********/



struct {
	der_t distinguishedName;
	der_t lifecycleState;
} fork;



/* Open a PullayBack for Life Cycle Management.
 *
 * When our PulleyBack is opened, we load the external program
 * for each kind of life cycle.  We encapsulate them so that we
 * can cyclically pipe in two kinds of lines: *( DN, lcstate )
 *
 * The number of variables must be 2, for DN and lcstate.
 *
 * The handle returned is an lcenv pointer.
 *
 * #TODO# Create a thread to handle timeouts and live in lcenv.
 */
void *pulleyback_open (int argc, char **argv, int varc) {
	if ((argc < 2) || (varc != 2)) {
		errno = EINVAL;
		return NULL;
	}
	int argi;
	for (argi=1; argi<argc; argi++) {
		char sep = argv [argi] [idlen (argv [argi])];
		if (sep != '=') {
			errno = EINVAL;
			return NULL;
		}
	}
	// Arguments look good.  Allocate a structure for it.
	int bad = 0;
	struct lcenv *lce = calloc (sizeof (struct lcenv) + (argc-2) * sizeof (struct lcdriver), 1);
	if (lce == NULL) {
		errno = ENOMEM;
		bad = 1;
		goto done;
	}
	//
	// lco_first reset to NULL by calloc()
	// env_txncycle reset to NULL by calloc()
	// All lcdriver have a cmdname NULL and cmdpipe NULL, which is safe
	//
	// Now to fill lcdriver: cmdname, cmdpipe, cmdproc.
	lce->cnt_cmds = argc - 1;
	struct lcdriver *lcd = &lce->lcd_cmds [0];
	for (argi=1; argi<argc; argi++) {
		size_t argl = idlen (argv [argi]);
		lcd->cmdname = strndup (argv [argi], argl);
		lcd->cmdpipe = popen (argv [argi] + argl + 1, "w");
		if ((lcd->cmdname == NULL) || (lcd->cmdpipe == NULL)) {
			// errno is already set
			bad++;
		}
		lcd++;
	}
	// Return the result
done:
	if (bad > 0) {
		if (lce != NULL) {
			pulleyback_close ((void *) lce);
			lce = NULL;
		}
	}
	return lce;
}


/* Close a PulleyBack for Life Cycle Management.
 *
 * #TODO# Shutdown the thread living in the lcenv structure.
 */
void pulleyback_close (void *pbh) {
	struct lcenv *lce = (struct lcenv *) pbh;
	// Inasfar as we are in a transaction, break it off
	if (txn_isactive (lce)) {
		txn_break (lce);
	}
	// All lcobjects and lcstates will now be cleaned up
	struct lcobject *lco = lce->lco_first;
	while (lco != NULL) {
		struct lcobject *lcn = lco->lco_next;
		free_lcobject (&lco);
		lco = lcn;
	}
	// Cleanup lcdriver entries, inasfar as they are present:
	int argi = 0;
	struct lcdriver *lcd = &lce->lcd_cmds [0];
	while (argi++ < lce->cnt_cmds) {
		if (lcd->cmdpipe != NULL) {
			int chex = pclose (lcd->cmdpipe);
			if (chex != 0) {
				syslog (LOG_ERR, "Error exit value %d from #%d commdn pipe %s", chex, argi-1, lcd->cmdname ? lcd->cmdname : "(failed)");
			}
			lcd->cmdpipe = NULL;
		}
		if (lcd->cmdname != NULL) {
			free (lcd->cmdname);
			lcd->cmdname = NULL;
		}
		lcd++;
	}
	free (lce);
}


/* INTERNAL FUNCTION:
 *
 * Add or delete an entry in the current transaction, if one is open.
 * This internal function is run by the pulleyback_add and pulleyback_del
 * functions, because they are so similar.  The variable add_not_del
 * distinguishes on details.
 *
 * Return 1 on success and 0 on failure, including when no
 * transaction is successfully open or when input data violates our
 * assumptions.
 */
struct fork {
	der_t dn;
	der_t lcs;
};
static int _int_pb_addnotdel (bool add_not_del,
				struct lcenv *lce, struct fork *fd) {
	bool success = txn_isactive (lce);
	char  *dnptr, *lcsptr;
	size_t dnlen,  lcslen;
	success = success && parse_der (fd->dn,  &dnptr,  &dnlen );
	success = success && parse_der (fd->lcs, &lcsptr, &lcslen);
	if (!success) {
		return 0;
	}
	struct lcobject *lco = find_lcobject (lce->lco_first, dnptr, dnlen);
	struct lcstate **plcs = NULL;
	if (lco != NULL) {
		plcs = find_lcstate_ptr (& lco->lcs_toadd,
		                         lco->lcs_todel,
		                         lcsptr, lcslen);
	}
	if (add_not_del) {
		// While adding, we may have to add an lcobject for a DN
		if (lco == NULL) {
			lco = new_lcobject (dnptr, dnlen);
			lco->lco_next = lce->lco_first;
			lce->lco_first = lco;
		}
		// While adding, we may have to add an lcstate for an LCS
		if (plcs == NULL) {
			struct lcstate *lcs;
			lcs = new_lcstate (lco, lcsptr, lcslen);
			lcs->lcs_next = lco->lcs_toadd;
			lco->lcs_toadd = lcs;
		}
	} else {
		// While deleting, we require all data to pre-exist
		success = success && (lco != NULL) && (plcs != NULL);
		if (success) {
			// Cut out the found lcstate (which ends in lcs)
			struct lcstate *lcs = *plcs;
			*plcs = lcs->lcs_next;
			// Prefix the found lcstate (in lcs) to lcs_todel
			plcs = & lco->lcs_first;
			while (*plcs != lco->lcs_todel) {
				plcs = & (*plcs)->lcs_next;
			}
			lcs->lcs_next = *plcs;
			lco->lcs_todel =
			*plcs = lcs;
		}
	}
	if (!success) {
		txn_break (lce);
	}
	return success ? 1 : 0;
}


/* Add an entry to the current transaction, if one is open.
 * Since varc is assured to be 2, the forkdata holds two
 * values, interpreted as distinguishedName and lifecycleState.
 *
 * Return 1 on success and 0 on failure, including when no
 * transaction is successfully open or when input data violates our
 * assumptions.
 */
int pulleyback_add (void *pbh, der_t *forkdata) {
	struct lcenv *lce = (struct lcenv *) pbh;
	struct fork *fd = (struct fork *) forkdata;
	return _int_pb_addnotdel (true, lce, fd);
}


/* Delete an entry from the current transaction, if one is open.
 * Since varc is assured to be 2, the forkdata holds two
 * values, interpreted as distinguishedName and lifecycleState.
 *
 * Return 1 on success and 0 on failure, including when no
 * transaction is successfully open or when input data violates our
 * assumptions.
 */
int pulleyback_del (void *pbh, der_t *forkdata) {
	struct lcenv *lce = (struct lcenv *) pbh;
	struct fork *fd = (struct fork *) forkdata;
	return _int_pb_addnotdel (false, lce, fd);
}


/* Remove all data from the current transaction.
 */
int pulleyback_reset (void *pbh) {
	struct lcenv *lce = (struct lcenv *) pbh;
	if (!txn_isactive (lce)) {
		return 0;
	}
	txn_emptydata (lce);
	return 1;
}


/* Test if the current transaction would succeed.
 * This is an elementary test if the transaction has broken internally.
 * The potential of this optional function is that two-phase commit
 * can be used, thus allowing safe collaborations with other transactional
 * resources (at most one can be one-phase commit, in fact, and we don't
 * feel it should be us who holds back other programs).
 */
int pulleyback_prepare   (void *pbh) {
	struct lcenv *lce = (struct lcenv *) pbh;
	return txn_isactive (lce) ? 1 : 0;
}


/* Commit the current transaction; this may or may not be after prepare,
 * so there is a risk that it fails at this point.
 */
int pulleyback_commit    (void *pbh) {
	struct lcenv *lce = (struct lcenv *) pbh;
	if (!txn_isactive (lce)) {
		// Caller had better used used pulleyback_prepare()
		return 0;
	}
	txn_done (lce);
	return 1;
}


/* Rollback the current transaction.  Internally, there may not even
 * be a left-over from one; in this case, return trivially.  This is
 * to be expected, for instance as the result of individual failures
 * during add and del of lcstate.
 */
void pulleyback_rollback (void *pbh) {
	struct lcenv *lce = (struct lcenv *) pbh;
	if (txn_isactive (lce)) {
		txn_break (lce);
	}
}


/* Merge two transactions.  The commit or failure of one will lead
 * to the same result in the other.
 */
int pulleyback_collaborate (void *pbh1, void *pbh2) {
	struct lcenv *lce1 = (struct lcenv *) pbh1;
	struct lcenv *lce2 = (struct lcenv *) pbh2;
	if (txn_isactive (lce1)) {
		if (txn_isactive (lce2)) {
			// both transactions live, so merge their cycles
			struct lcenv *one1 = lce1->env_txncycle;
			struct lcenv *one2 = lce2->env_txncycle;
			struct lcenv *two1 = one1->env_txncycle;
			struct lcenv *two2 = one2->env_txncycle;
			one1->env_txncycle = two2;
			one2->env_txncycle = two1;
			return 0;
		} else {
			// lce2 broke down, so lce1 should also be broken
			txn_break (lce1);
		}
	} else {
		if (txn_isactive (lce2)) {
			// lce1 broke down, so lce2 should also be broken
			txn_break (lce1);
		} else {
			// both transactions broke down, trivially accept
			;
		}
	}
	return 1;
}

