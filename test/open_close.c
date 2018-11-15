/* Open and close the Pulley Backend, without intermediate actions.
 * We shall just try to print the lcenv that (we happen to know) is in
 * the handle.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>

#include "lifecycle.h"


void *pulleyback_open (int argc, char **argv, int varc);
void pulleyback_close (void *pbh);
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
	debug_lcenv (lce);
	pulleyback_close ((void *) lce);
	exit (0);
}
