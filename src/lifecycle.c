/* PulleyBack driver with Life Cycle Management.
 *
 * This module is what is called an output driver in SteamWorks Pulley.
 * It is loaded into a PulleyScript as a dynamic library, and called to
 * add or remove the forks that are defined in PulleyScript.  These forks
 * must be a pair of a distinguishedName and a lifecycleState attribute.
 *
 * The lifecycleState denotes timed events (including as soon as possible)
 * and awaiting changes in other lifecycleState sequences in the same
 * lifecycleObject.  It works like a simplified form of CSP.
 *
 * This backend handles the interdependencies between the life cycles,
 * and allows the timed events to be processed without any further
 * cross-dependencies.  This processing of timed events is performed by
 * passing a distinguishedName and lifecycleState to a handler process
 * that is specific for the lifecycleState.  The handler should take
 * action and, when successful, change the lifecycleState in LDAP, which
 * then leads back to this plugin, which examines it for continued work.
 *
 * The current state is shown in LDAP, by a dot that separates past and
 * future actions.  The handler's task is to move the dot forward, ideally
 * until the end.  When the end is reached, the lifecycleState no longer
 * appears here, because it is done.
 *
 * This component was designed for the ARPA2 KeyMaster, infrastructure
 * for managing keys in spite of their confusing collective state that
 * might combine X.509, DANE, ACME.  Things like DNS caching makes this
 * a rather nettly issue to do well under massive automation.  This is
 * why the KeyMaster is a solid part of the IdentityHub, which in turn
 * is the second phase of the InternetWide Architecture described at
 * http://internetwide.org and worked out in many ARPA2 projects on
 * https://github.com/arpa2 and http://<project>.arpa2.net websites.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */



#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include <assert.h>

#include <time.h>
#include <syslog.h>
#include <errno.h>
#include <regex.h>
#include <pthread.h>

//TODO// Transition lco_first/_next to UT_hash iteration?
#include "uthash.h"
//TODO// Include pulleyback.h locally (for now)
#include "pulleyback.h"
#include "lifecycle.h"



#ifdef DEBUG
static void debug (char *fmt, ...) {
	va_list argl;
	fprintf (stderr, "DEBUG: ");
	fflush (stderr);
	va_start (argl, fmt);
	vfprintf (stderr, fmt, argl);
	va_end (argl);
	fprintf (stderr, "\n");
	fflush (stderr);
}
#else
static inline debug (char *fmt, ...) {
	;
}
#endif


/* External Dependencies:
 *
 * We use "uthash.h" for quickly locating a distinguishedName, which may
 * occur relatively frequently.  The same does not apply to lifecycleState,
 * which only occurs during addition and removal of the value.
 *
 * For time-based information, the best is probably to collect only those
 * that expire in the next 10 seconds or so, and to search for the double
 * value and so on until done.  It is pretty useless to want to sort the
 * while timer loop.  This is why we prefer not to use "utlist.h" for
 * lists.
 *
 * Note that "uthash.h" and "utlist.h" are macro trick boxes only.
 *
 * We can use the POSIX functions for regular expressions in C, so the
 * regcomp(), regexec(), regfree() and regerror() couple.  Those assume
 * NUL-terminated strings, so we need to be careful using DER information.
 * It may be beneficial to have lifecycleState on stack as a C string,
 * while checking the absense of internal NUL characters (strncpy() output?)
 * and use that while processing an action that involves those strings.
 */


//TODO// Cleanup routines for DNs without LCS left



/********** UTILITY FUNCTIONS **********/



/* Find the length of an identifier */
size_t idlen (char *idstr) {
	size_t rv = 0;
	while (idstr [rv] != '\0') {
		char c = idstr [rv];
		if ((isalnum (c)) || (c == '-') || (c == '_')) {
			rv++;
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


/* Check the syntax of a lifecycleState attribute value.
 * The first run will compile the value.  Removal is not forced but
 * is normal operating system service at exit().  The life time for the
 * compiled regular expression is unbounded.
 */
#ifndef LIFECYCLESTATE_RE
#warning "No lifecycleState grammer defined as LIFECYCLESTATE_RE yet"
#define LIFECYCLESTATE_RE ".*"
#endif
bool grammar_lcstate (char *lcs) {
	static bool done = false;
	static regex_t re;
	// Compile the regex if so desired
	if (!done) {
		debug ("Compiling lcs regex \"%s\"", LIFECYCLESTATE_RE);
		assert (0 == regcomp (&re,
				LIFECYCLESTATE_RE,
				REG_EXTENDED | REG_NOSUB));
		done = true;
	}
	// Use the regex that was previously compiled
	debug ("Testing lcs grammar \"%s\"", lcs);
	return 0 == regexec (&re, lcs, 0, NULL, 0);
}


/* Check the syntax of a distinguishedName attribute value.
 * The first run will compile the value.  Removal is not forced but
 * is normal operating system service at exit().  The life time for the
 * compiled regular expression is unbounded.
 */
#ifndef DISTINGUISHEDNAME_RE
#warning "No distinguishedName grammar defined as DISTINGUISHEDNAME_RE yet"
#define DISTINGUISHEDNAME_RE ".*"
#endif
bool grammar_dn (char *dn) {
	static bool done = false;
	static regex_t re;
	// Compile the regex if so desired
	if (!done) {
		debug ("Compiling dn regex \"%s\"", DISTINGUISHEDNAME_RE);
		assert (0 == regcomp (&re,
				DISTINGUISHEDNAME_RE,
				REG_EXTENDED | REG_NOSUB));
		done = true;
	}
	// Use the regex that was previously compiled
	debug ("Testing dn grammar \"%s\"", dn);
	return 0 == regexec (&re, dn, 0, NULL, 0);
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
	new->lcs_next = lco->lcs_toadd;
	lco->lcs_toadd = new;
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
 *
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


/* For debugging purposes, print lifecycleState.
 */
#ifdef DEBUG
void debug_lcstate (struct lcstate *lcs, char *what_to_do) {
	if (what_to_do == NULL) {
		what_to_do = "";
	}
	debug (" | +-----> lifecycleState%s: %s", what_to_do, lcs->txt_attr);
	debug (" | |       ofs_next=%d tim_next=%d cnt_missed=%d", lcs->ofs_next, lcs->tim_next, lcs->cnt_missed);
}
#endif


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
	new->tim_first = MAX_TIME_T;
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
		lcs->lcs_next = NULL;
		free_lcstate (&lcs);
		lcs = lcn;
	}
	free (*lco);
	*lco = NULL;
}


/* Find a lifecycleObject in an UT_hash table.
 * The value to be found usually comes from DER, so it is given as
 * a memory (ptr,len) pair.
 * Return NULL when the exact string was not found.
 */
struct lcobject *find_lcobject (struct lcobject *lco_dnhash,
				char *mem, size_t memlen) {
	struct lcobject *retval;
	HASH_FIND (hsh_dn, lco_dnhash, mem, memlen, retval);
	return retval;
}


/* For debugging purposes, print lifecycleObject information.
 */
#ifdef DEBUG
void debug_lcobject (struct lcobject *lco) {
	debug (" +-+---> dn: %s", lco->txt_dn);
	debug (" | |     tim_first=%d", lco->tim_first);
	struct lcstate *lcs = lco->lcs_first;
	char *what_to_do = NULL;
	if (lco->lcs_todel != NULL) {
		what_to_do = ";KEEP";
	}
	if (lco->lcs_toadd != NULL) {
		lcs = lco->lcs_toadd;
		what_to_do = ";ADD";
	}
	while (lcs != NULL) {
		if (lcs == lco->lcs_todel) {
			what_to_do = ";DEL";
		} else if (lcs == lco->lcs_first) {
			what_to_do = ";KEEP";
		}
		debug_lcstate (lcs, what_to_do);
		lcs = lcs->lcs_next;
	}
}
#endif



/********** TIMER FUNCTIONS **********/



/* Mark the firing time in an lcobject as "dirty", that is,
 * as being in need of an update.
 */
void smudge_lcobject_firetime (struct lcobject *lco) {
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
bool smudged_lcstate_firetime (struct lcstate *lcs) {
	return lcs->tim_next == 0;
}


/* Test if the firing time in an lcobject is "dirty", that is,
 * needs an update.
 */
bool smudged_lcobject_firetime (struct lcobject *lco) {
	return lco->tim_first == 0;
}


/* When the next event is '@' or '=' type, test when it may fire.
 */
time_t update_lcstate_firetime (struct lcstate *lcs) {
	time_t update = MAX_TIME_T;
	if (lcs->typ_next != '@') {
		goto done;
	}
	char *timestr = strchr (lcs->txt_attr + lcs->ofs_next, '@');
	if (timestr == NULL) {
		goto done;
	}
	timestr++;
	if (!isdigit (*timestr)) {
		// '=' or ' ' or '\0', but not a timestamp
		update = time (NULL);
		goto done;
	}
	unsigned long stamp = strtoul (timestr, &timestr, 10);
	if (stamp == 0) {
		update = time (NULL);
		goto done;
	}
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
	lco->tim_first = MAX_TIME_T;
	struct lcstate *lcs = lco->lcs_first;
	while (lcs != NULL) {
		if (smudged_lcstate_firetime (lcs)) {
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
 * if we acted on a missing attribute.  It is instead called from the
 * service thread.
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
 * if we acted on a missing attribute.  It is instead called from the
 * service thread.
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
 * if we acted on a missing attribute.  It is instead called from the
 * service thread.
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



/********** SERVICE THREAD **********/



/* When a backend instance is openened, it is given its own thread.
 * When the backend instance is closed, the thread is taken away.
 * We refer to this thread as the service thread of an lcenv; it
 * exists only because Pulley retains control while we would like
 * to respond to timeouts, not just LDAP changes.
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
 */



/* Threads synchronise as follows:
 *
 *  0. The threads consist of a pulley backend and individual service
 *     threads that each handle an lcenv with its subordinate lcobject
 *     and lcstate data.
 *  1. The new thread will loop, each time checking if the LCE_SERVICED
 *     is still set in lce_flags.  This is always done after waiting for
 *     a condition signal or a timeout.
 *  2. The main program never cancels the service thread, but resets the
 *     flag and sends a condition signal while it knows the service
 *     thread is waiting for it.
 *  3. The service thread normally sits waiting for a condition, which is
 *     that new work has arrived.  A signal is sent by any txn_done(),
 *     and spurious signals should also not wreak more heavoc than making
 *     another run.  During the wait, changes to the LCE_SERVICED flag in
 *     lce_flags might be made if the service thread needs to finish.
 *  4. Upon receiving the condition singal, a complete run through the
 *     logic is made.  This is another loop however, and it is skipped
 *     when LCE_SERVICED is no longer set in lce_flags.
 *  5. When a timer has been set, the condition wait is embellished with
 *     its expiration time.  This is another trigger that could lead to
 *     a spark of activity in the service thread, though specific to the
 *     findings during the previous loop run.  The signal indicates whether
 *     other things might also have changed.
 *  6. The service thread and pulley backend share a mutex, which protects
 *     the condition, but also serves to decide who may make changes to the
 *     lcenv and any lcobject and lcstate underneath.  Note that this is a
 *     strict hierarchy, without sharing between threads.  Between txn_open()
 *     and either txn_break() or txn_done(), the mutex is held by the
 *     transaction.  After a preliminary txn_break() the mutex is already
 *     gone, and no signal sent, but pulley may still believe it is using a
 *     transaction.  Since no further changes are made, this is fine.
 */



/* When a service fires, run over all registered lcstate that have a timer
 * set to at most the lcobject first firing time; this is always at least
 * one lcstate.
 *
 * During the setup of a Pulley Backend instance, a series of drivers for
 * lifecycle-named processes was openend with popen() and kept in the
 * lcenv.  Write two lines to the popen()ed process, one holding the
 * distinguishedName of the lcobject, the second with the lifecycleState
 * from the lcstate.
 *
 * TODO: Error handling; processes can fail, and what then?  Use ferror()?
 */
void service_fire_timer (struct lcobject *lco, struct lcenv *lce) {
	// Find at least one lcstate to fire
	time_t timer = lco->tim_first;
	bool fired_some_lcstate_timer = false;
	struct lcstate *lcs = lco->lcs_first;
	debug ("Looking for timer %d", timer);
	while (lcs != NULL) {
		// See if this lcstate wants to fire
		debug ("Considering type '%c' timer %d", lcs->typ_next, lcs->tim_next);
		if ((lcs->typ_next == '@') && (lcs->tim_next <= timer)) {
			char  *lcname    = lcs->txt_attr;
			size_t lcnamelen = idlen (lcname);
			// Iterate over the lcdriver list
			struct lcdriver *lcd = lce->lcd_cmds;
			uint32_t lcdnum      = lce->cnt_cmds;
			while (lcdnum-- > 0) {
				debug ("Testing lcdriver %s", lcname);
				if (0 == strmemcmp (lcd->cmdname,
						lcname, lcnamelen)) {
					fprintf (lcd->cmdpipe, "%s\n%s\n",
						lco->txt_dn,
						lcs->txt_attr);
					fflush (lcd->cmdpipe);
					fired_some_lcstate_timer = true;
					break;
				}
				lcd++;
			}
		}
		// Move to the next lcstate for this lcobject
		lcs = lcs->lcs_next;
	}
	assert (fired_some_lcstate_timer);
}


/* Pass through all events of all objects, and check any lcname?events
 * that can be advanced.  Any other types, such as '@' and '=' will
 * block further progress, and count as things to report to the handler
 * for the lifecycle, so it may cycle back through LDAP with updates.
 */
void service_advance_events (struct lcenv *lce) {
	struct lcobject *lco = lce->lco_first;
	// One run suffices, because objects don't communicate
	while (lco != NULL) {
		advance_lcobject_events (lco);
		lco = lco->lco_next;
	}
}


/* Pass through all objects, recomputing their timers when they are smudged
 * and the type is that of a timer, and finally sort the most likely timers
 * to fire soon.
 *
 * The "most likely timers" are a bit like the trickery of "utlist.h" sorting,
 * but the sorting is incomplete.  Only the beginning of the list ends up in
 * order.  Most of the remainder is left in the order it is at.  The entire
 * list is traversed however; this is generally necessary because there may
 * be new timers due to the advancing of services.
 *
 * The selection of "most likely timers" is a gradual process, and works
 * best with the most recent timers in the beginning.  The idea is to have
 * those in there that are at most twice as long away from now as the first
 * timer to expire.  Negative delays pass immediately, of course.  The ones
 * left are sorted by time.
 *
 * The processing that takes care of this is a bit like mitochondria digesting
 * chains of sugars or fats.  Taking a bit from the top, process it, move on.
 * When the time is too far in the future, it is left where it is, on the tail
 * behind the sorted list.  When the time is new enough, it is taken out and
 * inserted in the right place in the (hopefully short) prefix list.
 *
 * Once done, the first lcobject is the first to expire.  Any ones that fall
 * before now can be passed through immediately, but at some point the future
 * values show up, in sorted order.  From these, a future timer can be set
 * as an alternative to condition waiting.  But if the first is not a timer
 * then none exists in the list, and only condition waiting should be used.
 *
 * In the exceptional case that past timers take more time than the prepared
 * sorting time, the algorithm may need to run again.  This will be achieved
 * with an ugly goto statement, to avoid the suggestion that it would be a
 * structural action.
 */
void service_update_timers (struct lcenv *lce) {
	time_t now = time (NULL);
	int32_t accept_upto;
refresh:
	//
	// Construct a list with a time-ordered beginning.
	//
	accept_upto = 0x7fffffff;
	// Initially, we have no objects, just places to insert into
	struct lcobject **phd = & lce->lco_first;
	struct lcobject **ptl = phd;
	struct lcobject  *cur = *phd;
	// Loop over objects, possibly extending the head or tail
	while (cur = *ptl, cur != NULL) {
		bool use = false;
		// If needed, update the firing time
		if (smudged_lcobject_firetime (cur)) {
			update_lcobject_firetime (cur);
		}
		// Find the future timing
		if (cur->tim_first <= now) {
			// Timer should have fired
			use = true;
		} else {
			// Timer is in the future
			time_t future = cur->tim_first - now;
			if (future <= accept_upto) {
				// Acceptably sized future
				// (Initially matches almost anything)
				use = true;
				if (future < accept_upto/2) {
					// Radically closer than before
					accept_upto = future * 2;
				}
			}
		}
		// We now know if cur should be taken out for sorting
		if (use) {
			// Remove cur from the tail
			*ptl = cur->lco_next;
			cur->lco_next = NULL;
			// Find the place for cur after *phead
			struct lcobject **cmp = phd;
			time_t curfire = cur->tim_first;
			while (*cmp != NULL) {
				if ((*cmp)->tim_first > curfire) {
					break;
				}
				cmp = & (*cmp)->lco_next;
			}
			// Insert cur before *cmp (which may be NULL)
			cur->lco_next = *cmp;
			if (cmp == ptl) {
				// Exceptional, insertion at the tail
				// Avoid seeing the same object again
				ptl = & cur->lco_next;
			}
			*cmp = cur;
			// Unusual: keep ptl because *ptl has moved
			continue;
		} else {
			// Current-cursor iteration beyond unchanged *ptl
			ptl = & cur->lco_next;
		}
	}
	//
	// Run any events up to now in the list.
	//
	time_t newnow;
	struct lcobject *lco = lce->lco_first;
	while (newnow = time (NULL),
			(lco != NULL) && (lco->tim_first <= newnow)) {
		if (lco->tim_first == (time_t) -1) {
			//TODO// Quick Hack.  We set -1 in this routine...?
			debug ("TODO: Quick Hack -- we set -1 in tim_first, probably in this routine?!?");
			break;
		}
		// Hurry!  We should already have done this!
		debug ("service_fire_timer() called because lco->tim_first %d before newnow %d", lco->tim_first, newnow);
		service_fire_timer (lco, lce);
		// Rework the firing time; more lcstate may want to fire
		update_lcobject_firetime (lco);
		// Only iterate when there is no more lcstate to fire
		if (lco->tim_first > newnow) {
			lco = lco->lco_next;
		}
	}
	if (newnow - now > accept_upto) {
		// We ran so much work that the partial sorting is drained
		goto refresh;
	}
	//
	// The first lcobject to fire is now in lco_first, if any.
	//
	// Return.
}


/* We have done all we could, and are now waiting for something positive
 * to come our way.  This may take one of two forms:
 *  - a condition signal over lce_sigpost, indicating a txn_done()
 *  - a timer expiring, namely the first returned after service_update_timers()
 * Note that the timer is optional; there may be none at all.
 */
void service_wait (struct lcenv *lce) {
	// Decide if a timer is waiting to expire
	time_t first_expiration = MAX_TIME_T;
	if (lce->lco_first != NULL) {
		first_expiration = lce->lco_first->tim_first;
	}
	bool with_timer = first_expiration < MAX_TIME_T;
	// Wait for a condition, with or without a timer
	if (with_timer) {
		// Setup absolute time structure
		struct timespec abstime;  /* tv_sec, tv_nsec */
		memset (&abstime, 0, sizeof (abstime));
		abstime.tv_sec  = first_expiration;
		debug ("Service thread: Upcoming wait ends at %d", first_expiration);
		// Wait for a signal or reaching the absolute time
		assert (!pthread_cond_timedwait (
				&lce->pth_sigpost,
				&lce->pth_envown,
				&abstime));
		debug ("Service thread: Wakeup caused by commit, timeout or request to finish");
	} else {
		// Wait for a signal but not for a certain time
		assert (!pthread_cond_wait (
				&lce->pth_sigpost,
				&lce->pth_envown));
		debug ("Service thread: Wakeup caused by commit or request to finish");
	}
}


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
void *service_main (void *ctx) {
	struct lcenv *lce = (struct lcenv *) ctx;
	assert (lce != NULL);
	// We claim lcobject and lcstate access
	assert (!pthread_mutex_lock (&lce->pth_envown));
	debug ("Service thread: Started");
	// Enter the main loop of the service thread
	while (lce->lce_flags & LCE_SERVICED) {
		// Advance any events that can proceed right now
		debug ("Service thread: Advancing lcname?evname events");
		service_advance_events (lce);
		// Update timers and find the first @timer to fire
		debug ("Service thread: Updating timers");
		service_update_timers (lce);
		// Wait for commit from Pulley, or optional timer expiration
		debug ("Service thread: Waiting for commit (or timer expiration)");
		service_wait (lce);
	}
	// Free our mutex lock so the main thread can grab it back
	debug ("Service thread: Stopping");
	pthread_mutex_unlock (&lce->pth_envown);
	pthread_exit (NULL);
	return NULL;
}


/* Start the service thread.
 */
void service_start (struct lcenv *lce) {
	// Check and set the LCE_SERVICED flag to allow looping
	assert ((lce->lce_flags & LCE_SERVICED) == 0);
	lce->lce_flags |= LCE_SERVICED;
	// Prepare mutex and wait condition, then create the service thread
	assert (!pthread_mutex_init (&lce->pth_envown,  NULL));
	assert (!pthread_cond_init  (&lce->pth_sigpost, NULL));
	assert (!pthread_create     (&lce->pth_service, NULL,
	                             service_main, (void *) lce));
}


/* Stop the service thread, and wait until it finishes.
 */
void service_stop (struct lcenv *lce) {
	// Check and clear the LCE_SERVICED flag to end looping
	assert ((lce->lce_flags & LCE_SERVICED) != 0);
	lce->lce_flags &= ~LCE_SERVICED;
	// Block the service thread at the end of the loop
	assert (!pthread_mutex_lock (&lce->pth_envown));
	debug ("Sending final signal to service thread");
	assert (!pthread_cond_signal (&lce->pth_sigpost));
	assert (!pthread_mutex_unlock (&lce->pth_envown));
	// Stop the service thread and cleanup wait condition and mutex
	void *exitval;
	assert (!pthread_join (lce->pth_service, &exitval));
	// Nobody is watching, so we can safely cleanup resources
	assert (!pthread_cond_destroy  (&lce->pth_sigpost));
	assert (!pthread_mutex_unlock  (&lce->pth_envown));
	//LINUX_FAILS// assert (!pthread_mutex_destroy (&lce->pth_envown));
	assert ((!pthread_mutex_destroy (&lce->pth_envown) || (errno == 0)));
}



/********** TRANSACTION SUPPORT **********/



/* Test if an internal transaction is active on the lcenv.
 * This is independent of what the Pulley Backend communicates;
 * Additionals and removals by Pulley silently create a new
 * transaction, but failure of an lcenv is shown by txn_isaborted()
 * to stop that and linger until pulleyback_rollback() or a falsely
 * informed pulleyback_commit() is sent.
 */
bool txn_isactive (struct lcenv *lce) {
	return lce->env_txncycle != NULL;
}


/* Test if an internal transaction has aborted.  This should be
 * mutual exclusive with txn_isactive().
 */
bool txn_isaborted (struct lcenv *lce) {
	return 0 != (lce->lce_flags & LCE_ABORTED);
}


/* Raise the aborted flag on an internal transaction.
 */
void txn_isaborted_set (struct lcenv *lce) {
	assert (!txn_isactive (lce));
	lce->lce_flags |= LCE_ABORTED;
}


/* Clear the aborted flag on an internal transaction.
 */
void txn_isaborted_clr (struct lcenv *lce) {
	assert (!txn_isactive (lce));
	lce->lce_flags &= ~LCE_ABORTED;
}


/* For debugging purposes, print lcenv information.
 */
#ifdef DEBUG
void debug_lcenv (struct lcenv *lce) {
	int cyclen = 0;
	if (lce->env_txncycle != NULL) {
		struct lcenv *lce2 = lce;
		do {
			cyclen++;
			lce2 = lce2->env_txncycle;
		} while (lce2 != lce);
	}
	debug ("-+---> txn_isactive=%d, txn_isaborted=%d, txn_cyclen=%d", txn_isactive (lce), txn_isaborted (lce), cyclen);
	struct lcobject *lco = lce->lco_first;
	while (lco != NULL) {
		debug_lcobject (lco);
		lco = lco->lco_next;
	}
}
#endif


/* Open a fresh transaction.  This is an internal transaction,
 * which initiates when needed for data changes.  It may end
 * before the last change has come through, namely in the case
 * of errors.  The txn_isaborted() is then set in the lcenv to
 * inform later attempts by Pulley to finish the transaction.
 * The service thread is locked out from the data structures
 * between txn_open() and txn_done() or txn_break().
 */
void txn_open (struct lcenv *lce) {
	assert (! txn_isactive  (lce));
	assert (! txn_isaborted (lce));
	// Obtain ownership of this lcenv
	assert (!pthread_mutex_lock (&lce->pth_envown));
	// Create the smallest transaction cycle, containing just us
	lce->env_txncycle = lce;
	// Setup each lcobject for attribute changes
	struct lcobject *lco = lce->lco_first;
	while (lco != NULL) {
		assert (lco->lcs_toadd == NULL);
		assert (lco->lcs_todel == NULL);
		lco->lcs_toadd = lco->lcs_first;
		lco = lco->lco_next;
	}
	debug ("Transaction opened:");
	debug_lcenv (lce);
}


/* Break a transaction.  This recovers old state and disables any
 * further activity.  This may occur before Pulley knows about it,
 * namely when an error is detected.  This is indicated through
 * txn_isaborted() for the lcenv after txn_break().  After setting
 * this flag, the service thread is allowed to run again, handle
 * its timers and so on.
 */
void txn_break (struct lcenv *lce) {
	assert (txn_isactive (lce));
	struct lcenv *txnext;
	// Iterate over the transactional cycle, breaking all
	while (txnext = lce->env_txncycle, txnext != NULL) {
		// Break the transactional cycle in this lcenv
		lce->env_txncycle = NULL;
		// Undo the changes in all lcobject of this lcenv
		struct lcobject *lco = lce->lco_first;
		while (lco != NULL) {
			debug ("Removing in lcobject %s", lco->txt_dn);
			struct lcstate *lcs = lco->lcs_toadd;
			while (lcs != lco->lcs_first) {
				debug ("Removing lcstate %s", lcs->txt_attr);
				struct lcstate *next = lcs->lcs_next;
				lcs->lcs_next = NULL;
				free_lcstate (&lcs);
				lcs = next;
			}
			lco->lcs_toadd = NULL;
			lco->lcs_todel = NULL;
			lco = lco->lco_next;
		}
		// Communicate failure through the pulley backend
		txn_isaborted_set (lce);
		// Release the ownership hold on this lcenv
		assert (!pthread_mutex_unlock (&lce->pth_envown));
		// Move to the next lcenv in the transaction cycle, if any
		lce = txnext;
	}
	debug ("Transaction broken:");
	debug_lcenv (lce);
}


/* The current transaction is done.
 * Delete what was setup for deletion, add what was prepared.
 *TODO* Not actually deleting, and not wiping _todel pointer
 */
void txn_done (struct lcenv *lce) {
	assert (txn_isactive (lce));
	struct lcenv *txnext;
	// Iterate over the transactional cycle, committing all
	while (txnext = lce->env_txncycle, txnext != NULL) {
		// Break the transactional cycle in this lcenv
		lce->env_txncycle = NULL;
		// Commmit the changes in all lcobject of this lcenv
		struct lcobject **plco = & lce->lco_first;
		while (*plco != NULL) {
			struct lcobject *lco = *plco;
			struct lcstate **plcs = & lco->lcs_toadd;
			struct lcstate *next;
			while (next = *plcs, next != lco->lcs_todel) {
				plcs = & next->lcs_next;
			}
			*plcs = NULL;
			while (next != NULL) {
				struct lcstate *this = next;
				next = this->lcs_next;
				this->lcs_next = NULL;
				free_lcstate (&this);
			}
			lco->lcs_first = lco->lcs_toadd;
			lco->lcs_toadd = NULL;
			lco->lcs_todel = NULL;
			if (lco->lcs_first == NULL) {
				// Empty object.  Cleanup and resample *plco
				*plco = lco->lco_next;
				HASH_DELETE (hsh_dn, lce->lco_dnhash, lco);
				lco->lco_next = NULL;
				free_lcobject (&lco);
			} else {
				// Proper object.  Continue to next *plco
				plco = & lco->lco_next;
			}
		}
		// Communicate success to the service thread
		debug ("Signaling the Service thread about the commit");
		assert (!pthread_cond_signal (&lce->pth_sigpost));
		// Release the ownership hold on this lcenv
		assert (!pthread_mutex_unlock (&lce->pth_envown));
		// Move to the next lcenv in the transaction cycle, if any
		lce = txnext;
	}
	debug ("Transaction succeeded:");
	debug_lcenv (lce);
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



struct fork {
	der_t dn;
	der_t lcs;
};



/* Open a PullayBack for Life Cycle Management.
 *
 * When our PulleyBack is opened, we load the external program
 * for each kind of life cycle.  We encapsulate them so that we
 * can cyclically pipe in two kinds of lines: *( DN, lcstate )
 *
 * The number of variables must be 2, for DN and lcstate.
 *
 * The handle returned is an lcenv pointer.
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
		bad++;
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
	// Initialise and start the service thread
	service_start (lce);
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
 */
void pulleyback_close (void *pbh) {
	struct lcenv *lce = (struct lcenv *) pbh;
	// Inasfar as we are in a transaction, break it off
	if (txn_isactive (lce)) {
		txn_break (lce);
	}
	// Ask the service thread to exit, and wait for it to happen
	service_stop (lce);
	// All lcobjects and lcstates will now be cleaned up
	struct lcobject *lco = lce->lco_first;
	while (lco != NULL) {
		struct lcobject *lcn = lco->lco_next;
		HASH_DELETE (hsh_dn, lce->lco_dnhash, lco);
		lco->lco_next = NULL;
		free_lcobject (&lco);
		lco = lcn;
	}
	// Cleanup lcdriver entries, inasfar as they are present:
	uint32_t argi = 0;
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


/* Internal Function:
 *
 * Add or delete an entry in the current transaction, if one is open.
 * This internal function is run by the pulleyback_add and pulleyback_del
 * functions, because they are so similar.  The variable add_not_del
 * distinguishes on details.
 *
 * This function silently starts an internal transaction when none is
 * active yet.  The exception is when txn_isaborted() is set in the lcenv
 * to indicate that the current transaction has failed and the internal
 * transaction was txn_abort()ed on account of that.
 *
 * Return 1 on success and 0 on failure, including when no
 * transaction is successfully open or when input data violates our
 * assumptions.
 */
static int _int_pb_addnotdel (bool add_not_del,
				struct lcenv *lce, struct fork *fd) {
	// Continue the failure of preceding actions (and bypass activity)
	if (txn_isaborted (lce)) {
		// Stop right now if the transaction already aborted
		return 0;
	}
	// Silently open an internal transaction if needed
	if (!txn_isactive (lce)) {
		txn_open (lce);
	}
	// We now have an active, non-aborted transaction
	bool success = true;
	// Parse single DER attributes into ptr,len values
	char  *dnptr =  dnptr;
	char *lcsptr = lcsptr;
	size_t  dnlen = 0;
	size_t lcslen = 0;
	success = success && parse_der (fd->dn,  &dnptr,  &dnlen );
	success = success && parse_der (fd->lcs, &lcsptr, &lcslen);
	// Make ASCII strings (safe and fast when parse_der() did not run)
	char dnstr  [ dnlen+1];
	char lcsstr [lcslen+1];
	memcpy ( dnstr,  dnptr,  dnlen);
	memcpy (lcsstr, lcsptr, lcslen);
	dnstr  [dnlen ] = '\0';
	lcsstr [lcslen] = '\0';
	debug ("distinguishedName: %s",  dnstr);
	debug ("lifecycleState:    %s", lcsstr);
	// Verify the absense of inner NUL characters
	success = success && (memchr ( dnstr, '\0',  dnlen) == NULL);
	success = success && (memchr (lcsstr, '\0', lcslen) == NULL);
	// Validate the grammar of the distinguishedName and lifecycleState
	success = success && grammar_dn      ( dnstr);
	success = success && grammar_lcstate (lcsstr);
	// In case of failure, stop now and make no changes
	if (!success) {
		debug ("Failed to add or delete an attribute");
		// The transaction is open, so we must break it
		txn_break (lce);
		return 0;
	}
	// Try to locate the lcobject to work on -- NULL if not found
	struct lcobject *lco = find_lcobject (lce->lco_dnhash, dnstr, dnlen);
	struct lcstate **plcs = NULL;
	if (lco != NULL) {
		plcs = find_lcstate_ptr (& lco->lcs_toadd,
		                         lco->lcs_todel,
		                         lcsstr, lcslen);
	}
	// Split activity into addition and deletion
	if (add_not_del) {
		// While adding, we may have to add an lcobject for a DN
		if (lco == NULL) {
			debug ("Addition without lcobject, will add it");
			lco = new_lcobject (dnstr, dnlen);
			lco->lco_next = lce->lco_first;
			lce->lco_first = lco;
			HASH_ADD (hsh_dn, lce->lco_dnhash, txt_dn, dnlen, lco);
			debug_lcenv (lce);
		}
		// While adding, we may have to add an lcstate for an LCS
		success = success && (plcs == NULL);
		if (success) {
			debug ("Addition without lifecycleState, will add it");
			new_lcstate (lco, lcsstr, lcslen);
		} else {
			debug ("Doubly added lifecycleState, rejecting");
		}
	} else {
		// While deleting, we require all data to pre-exist
		success = success && (lco != NULL) && (plcs != NULL);
		if (success) {
			// Cut out the found lcstate (which ends in lcs)
			struct lcstate *lcs = *plcs;
			if (*plcs == lco->lcs_first) {
				lco->lcs_first = lcs->lcs_next;
			}
			*plcs = lcs->lcs_next;
			// Prefix the found lcstate (in lcs) to lcs_todel
			plcs = & lco->lcs_toadd;
			while (*plcs != lco->lcs_todel) {
				plcs = & (*plcs)->lcs_next;
			}
			lcs->lcs_next = *plcs;
			if (*plcs == lco->lcs_first) {
				lco->lcs_first = lcs;
			}
			lco->lcs_todel = lcs;
			*plcs = lcs;
		}
	}
	// Rollback the internal transaction if we failed
	if (!success) {
		txn_break (lce);
	}
	// Communicate to the Pulley Backend if we succeeded
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


/* Test if the current transaction would succeed.  This does not always
 * meant that a transaction is active; empty transactions succeed quite
 * easily.
 *
 * This is an elementary test if the transaction has broken internally.
 * The potential of this optional function is that two-phase commit
 * can be used, thus allowing safe collaborations with other transactional
 * resources (at most one can be one-phase commit, in fact, and we don't
 * feel it should be us who holds back other programs).
 */
int pulleyback_prepare   (void *pbh) {
	struct lcenv *lce = (struct lcenv *) pbh;
	// Only read txn_isaborted(); it is cleaned up in the decision
	return txn_isaborted (lce) ? 0 : 1;
}


/* Commit the current transaction; this may or may not be after prepare,
 * so there is a risk that it fails at this point.
 */
int pulleyback_commit    (void *pbh) {
	struct lcenv *lce = (struct lcenv *) pbh;
	if (txn_isaborted (lce)) {
		// Caller had better used used pulleyback_prepare()
		txn_isaborted_clr (lce);
		return 0;
	} else if (txn_isactive (lce)) {
		// Commit changes and return the result
		txn_done (lce);
		return 1;
	} else {
		// Trivial, nothing has been done
		return 1;
	}
}


/* Rollback the current transaction.  Internally, there may not even
 * be a left-over from one; in this case, return trivially.  This is
 * to be expected, for instance as the result of individual failures
 * during add and del of lcstate.
 */
void pulleyback_rollback (void *pbh) {
	struct lcenv *lce = (struct lcenv *) pbh;
	// Stop any transaction that may be active
	if (txn_isactive (lce)) {
		txn_break (lce);
	}
	// Suppress the txn_isaborted() flag that should now be raised
	txn_isaborted_clr (lce);
}


/* Merge two transactions.  The commit or failure of one will lead
 * to the same result in the other.
 */
int pulleyback_collaborate (void *pbh1, void *pbh2) {
	struct lcenv *lce1 = (struct lcenv *) pbh1;
	struct lcenv *lce2 = (struct lcenv *) pbh2;
	assert (txn_isactive (lce1) || txn_isaborted (lce1));
	assert (txn_isactive (lce2) || txn_isaborted (lce2));
	if (txn_isaborted (lce1)) {
		if (txn_isaborted (lce2)) {
			debug ("Broken txn #1 and #2, trivial to collaborate");
			return 1;
		} else {
			debug ("Broken txn #1, breaking #2 to collaborate");
			txn_break (lce2);
			return 1;
		}
	} else {
		if (txn_isaborted (lce2)) {
			debug ("Broken txn #2, breaking #1 to collaborate");
			txn_break (lce1);
			return 1;
		} else {
			debug ("Merging txn #1 and #2 to collaborate");
			struct lcenv *one1 = lce1->env_txncycle;
			struct lcenv *one2 = lce2->env_txncycle;
			struct lcenv *two1 = one1->env_txncycle;
			struct lcenv *two2 = one2->env_txncycle;
			one1->env_txncycle = two2;
			one2->env_txncycle = two1;
			return 0;
		}
	}
}

