/* Add and delete forks, in different orders, and with various intermittent
 * commits and aborts.
 *
 * Note that a commit will trigger the service thread too.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>

#include "lifecycle.h"
#include <steamworks/pulleyback.h>


void debug_lcenv (struct lcenv *lce);
void debug_lcobject (struct lcobject *lco);


int main (int argc, char **argv) {
	uint8_t *der_dn1 = (uint8_t *) "\x04\x1cuid=bakker,dc=orvelte,dc=nep";
	uint8_t *der_dn2 = (uint8_t *) "\x04\x1auid=smid,dc=orvelte,dc=nep";
	uint8_t *der_at1 = (uint8_t *) "\x04\x0dx . go@ gone@";
	uint8_t *der_at2 = (uint8_t *) "\x04\x19y aap@12345 . noot@ mies@";
	uint8_t *der11 [] = { der_dn1, der_at1 };
	uint8_t *der12 [] = { der_dn1, der_at2 };
	uint8_t *der21 [] = { der_dn2, der_at1 };
	uint8_t *der22 [] = { der_dn2, der_at2 };
	struct lcenv *lce;
	lce = (struct lcenv *) pulleyback_open (argc, argv, 2);
	if (lce == NULL) {
		fprintf (stderr, "Failed to open Pulley Backend\n");
		exit (1);
	}
	fprintf (stderr, "Adding <dn1,at1>: %d\n",
		pulleyback_add (lce, der11));
	fprintf (stderr, "Adding <dn1,at2>: %d\n",
		pulleyback_add (lce, der12));
	fprintf (stderr, "Adding <dn2,at2>: %d\n",
		pulleyback_add (lce, der22));
	fprintf (stderr, "Adding <dn2,at1>: %d\n",
		pulleyback_add (lce, der21));
	debug_lcenv (lce);
	fprintf (stderr, "Preparing PulleyBack for commit\n");
	if (pulleyback_prepare (lce) == 0) {
		fprintf (stderr, " --> failed\n");
	} else {
		fprintf (stderr, " --> success\n");
	}
	debug_lcenv (lce);
	fprintf (stderr, "Committing PulleyBack\n");
	if (pulleyback_commit (lce) == 0) {
		fprintf (stderr, " --> failed (SHOULD NOT HAPPEN)\n");
	}
	debug_lcenv (lce);
	fprintf (stderr, "Deleting <dn1,at1>: %d\n",
		pulleyback_del (lce, der11));
	debug_lcenv (lce);
	fprintf (stderr, "Deleting <dn1,at2>: %d\n",
		pulleyback_del (lce, der12));
	debug_lcenv (lce);
	fprintf (stderr, "Deleting <dn2,at1>: %d\n",
		pulleyback_del (lce, der21));
	debug_lcenv (lce);
	fprintf (stderr, "Deleting <dn2,at2>: %d\n",
		pulleyback_del (lce, der22));
	debug_lcenv (lce);
	fprintf (stderr, "Committing PulleyBack\n");
	if (pulleyback_commit (lce) == 0) {
		fprintf (stderr, " --> failed (SHOULD NOT HAPPEN)\n");
	}
	debug_lcenv (lce);
/*
	fprintf (stderr, "Aborting PulleyBack\n");
	pulleyback_rollback (lce);
	debug_lcenv (lce);
*/
	pulleyback_close ((void *) lce);
	fprintf (stderr, "Closed PulleyBack instance\n");
	exit (0);
}
