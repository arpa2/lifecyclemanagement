/* Open and close the Pulley Backend, without intermediate actions.
 * We shall just try to print the lcenv that (we happen to know) is in
 * the handle, and run some pointless operations on the empty transactions.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>

#include "lifecycle.h"
#include "pulleyback.h"


void debug_lcenv (struct lcenv *lce);
void debug_lcobject (struct lcobject *lco);
void debug_lcstate (struct lcstate *lcs);


int main (int argc, char **argv) {
	struct lcenv *lce;
	lce = (struct lcenv *) pulleyback_open (argc, argv, 2);
	if (lce == NULL) {
		fprintf (stderr, "Failed to open Pulley Backend\n");
		exit (1);
	}
	fprintf (stderr, "Opened PulleyBack instance\n");
	debug_lcenv (lce);
	fprintf (stderr, "Resetting PulleyBack (dropping all data)\n");
	pulleyback_reset (lce);
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
	fprintf (stderr, "Aborting PulleyBack\n");
	pulleyback_rollback (lce);
	debug_lcenv (lce);
	pulleyback_close ((void *) lce);
	fprintf (stderr, "Closed PulleyBack instance\n");
	exit (0);
}
