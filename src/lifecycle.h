/* Life Cycle Management based on LDAP structures.
 *
 * The objectClass 'lifecycleObject' allows zero or more 'lifecycleState'
 * attributes, each depicting a name and a sequential process of events,
 * with a dot as a separate word to mark the separate between past and
 * future.  Events can await a timeout (defaulting to as soon as possible)
 * or the occurrence of an event in another sequential process.
 *
 * This module is kept up to date by LDAP, and is fed with objects'
 * distinguishedName and lifecycleStates.  Based on these, it schedules
 * actions and sends actions to a shell.  This sending of actions will
 * continue until the lifecycleState is removed -- and, usually, replaced
 * with another value, which is in a more advanced state, as part of the
 * same transaction.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */



#include <time.h>

#include <pthread.h>

#include "uthash.h"



// One lifecycleState attribute value, stored as NUL-terminated ASCII.
//  - lcs_next 
//  - tim_next is the following timestamp for action.
//  - ofs_next is the offset of the next word (initially after the dot).
//  - typ_next is the character '@' or '?' or NUL for timer, event, done.
//  - cnt_missed is the number of missed occurrences (for exp fallback).
//  - txt_attr is the NUL-terminated attribute value.
//
struct lcstate {
	struct lcstate *lcs_next;
	time_t          tim_next;
	uint16_t        ofs_next;
	uint8_t         typ_next;
	uint8_t         cnt_missed;
	char            txt_attr [1];
};


// One lifecycleObject, as a distinguishedName with lifecycleState attributes.
//  - lco_next is the next lifecycleObject in a queue.
//  - lcs_first is the first lifecycleState in this lifecycleObject.
//  - lcs_toadd is a prefix to lcs_first to be added upon transaction commit.
//  - lcs_todel is a tail of lcs_first to be deleted upon transaction commit.
//  - tim_next is the first lifecycleState timer to expire (0 for "dirty").
//  - hsh_dn is a hash of the distinguishedName string.
//  - txt_dn is the NUL-terminated distinguishedName string.
//
// In general, lcstates are ordered as toadd, first, todel --
// with pointers to each stage.  Outside transactions, only first
// is meaningful, and this is consistently the one to read from.
// During a transaction, the others may grow state for future
// processing.  When a transaction aborts, its toadd is freed
// and its todel is forgotten and becomes part of first again.
// When a transaction succeeds, its todel is removed and its
// toadd becomes the new first.
//
struct lcobject {
	struct lcobject *lco_next;
	struct lcstate  *lcs_first;
	struct lcstate  *lcs_toadd;
	struct lcstate  *lcs_todel;
	time_t           tim_first;
	UT_hash_handle   hsh_dn;
	char             txt_dn [1];
};


// Is there a POSIX-standard way of quoting the maximum time_t value?
// The following assumes it is a signed type, so 32 bits go up to 2038.
//
#define MAX_TIME_T ((~(time_t)0)>>1)


// An lcdriver or Life Cycle Driver is a command to be opened with popen()
// to receive any number of pairs of lines: DN, attr.  Both are printed as
// the string that they are in LDAP, without headers or prefixes.  Neither
// should hold a newline, so this ought to work.
//
struct lcdriver {
	char *cmdname;
	FILE *cmdpipe;
};


// An LDAP environment, possibly mixing states of a transaction.
//
// LDAP environments represent a single backend instance, with its
// own called procedures and its own transactions.
//
// env_txncycle is NULL outside a transaction, otherwise it is
// a cycle of transactions that commit or fail together.  When
// a failure occurs, the transaction aborts and env_txncycle
// resets to NULL.  From this time on, transaction updates will
// fail consistently.
//
// pth_service is the service thread dedicated to this lcenv.
// pth_sigpost is the wait condition / signal post to inform it
// of a successful commit.  pth_envown is used to decide on who
// owns the lcobject and lcservice data underneath, as well as
// generally controls (most of) the lcenv object.
//
// lce_flags holds a number of flags about the lcenv:
//  - LCE_ABORTED indicates an aborted transaction
//  - LCE_SERVICED indicates that the service thread may continue
//
// LDAP environments are single-threaded, so re-entry is unsafe.
//
struct lcenv {
	pthread_mutex_t  pth_envown;	// lcobject/lcstat ownership?
	pthread_cond_t   pth_sigpost;	// signal from pulley, wait by service
	pthread_t        pth_service;	// this lcenv's service thread
	struct lcobject *lco_first;	// rd/wr only under pth_envown
	struct lcobject *lco_dnhash;	// owned by pulley backend
	struct lcenv    *env_txncycle;	// owned by pulley backend
	uint32_t         lce_flags;	// owned by pulley backend
	uint32_t         cnt_cmds;	// only written before service
	struct lcdriver  lcd_cmds [1];	// only written before service
};

#define LCE_ABORTED	0x00000001

#define LCE_SERVICED	0x00000002


// Grammar for lifecycleState in Extended Regular Expression form
//
#define IDENTIFIER_RE	"([a-zA-Z_-]+[0-9]*)"
#define TIMESTAMP_RE	"([0-9]+)"
#define VALUE_RE	"([^ .]*)"
//
#define LIFECYCLE_RE	IDENTIFIER_RE
#define EVENT_RE	IDENTIFIER_RE
#define VARIABLE_RE	IDENTIFIER_RE
//
#define NEXT_RE		"(" EVENT_RE "[@]" TIMESTAMP_RE "?" \
			"|" LIFECYCLE_RE "[?]" EVENT_RE ")"
//
#define DONE_RE		"(" EVENT_RE "[@]" TIMESTAMP_RE \
			"|" LIFECYCLE_RE "[?]" EVENT_RE \
			"|" VARIABLE_RE "[=]" VALUE_RE ")"
//
#define TO_DO_RE	"(" EVENT_RE "[@]" TIMESTAMP_RE "?" \
			"|" LIFECYCLE_RE "[?]" EVENT_RE \
			"|" VARIABLE_RE "[=]" VALUE_RE "?" ")"
//
#define LIFECYCLESTATE_RE \
			"^(" LIFECYCLE_RE "([ ]" DONE_RE ")*" \
			    "[ ][.][ ]" NEXT_RE "([ ]" TO_DO_RE ")*" \
			"|" LIFECYCLE_RE "([ ]" DONE_RE ")*" "[ ][.]" \
			")$"


// Grammar for distiguishedName in Extended Regular Expression form
//
#define KEYSTRING_RE	"([A-Za-z][A-Za-z0-9-]*)"
#define OID_RE		"([1-9][0-9]*([.][1-9][0-9]*)*)"
//
#define ATRTYPE_NAME_RE	KEYSTRING_RE
#define ATRTYPE_OID_RE	OID_RE
#define ATRTYPE_RE	"(" ATRTYPE_NAME_RE "|" ATRTYPE_OID_RE ")"
//
// RFC 4514 is much pickier than this
#define ATRVAL_RE	"([^,+]*|[\"][^,+\"]*[\"])"
//
#define ATTRTYPEVAL_RE	"(" ATRTYPE_RE "[=]" ATRVAL_RE ")"
//
#define RDN_RE		"(" ATTRTYPEVAL_RE "([+]" ATTRTYPEVAL_RE ")*" ")"
//
// RFC 4514 allows empty RDNSequences, printed as an empty string -- ignored
#define DISTINGUISHEDNAME_RE \
			"^(" RDN_RE "([,]" RDN_RE ")*" \
			")$"


