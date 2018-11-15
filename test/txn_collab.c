/* Open two transactions, and merge them.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>

#include "lifecycle.h"
#include "pulleyback.h"


void debug_lcenv (struct lcenv *lce);
void debug_lcobject (struct lcobject *lco);


// test1: lce1,lce2 each have 1 attr. they collaborate. break lce2.
void test1 (int argc, char **argv) {
	int argm = argc / 2;
	uint8_t *der_dn1 = (uint8_t *) "\x04\x1cuid=bakker,dc=orvelte,dc=nep";
	uint8_t *der_dn2 = (uint8_t *) "\x04\x1auid=smid,dc=orvelte,dc=nep";
	uint8_t *der_at1 = (uint8_t *) "\x04\x0dx . go@ gone@";
	uint8_t *der_at2 = (uint8_t *) "\x04\x19y aap@12345 . noot@ mies@";
	uint8_t *der_at3 = (uint8_t *) "\x04\x1by aap@12345 . noot@ . mies@";
	uint8_t *der1 [] = { der_dn1, der_at1 };
	uint8_t *der2 [] = { der_dn2, der_at2 };
	uint8_t *der3 [] = { der_dn2, der_at3 };
	struct lcenv *lce1, *lce2;
	lce1 = (struct lcenv *) pulleyback_open (argc-argm, argv+argm, 2);
	lce2 = (struct lcenv *) pulleyback_open (     argm, argv     , 2);
	if ((lce1 == NULL) || (lce2 == NULL)) {
		fprintf (stderr, "Failed to open Pulley Backend\n");
		exit (1);
	}
	fprintf (stderr, "Opened PulleyBack instances #1 and #2\n");
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Adding to instance #1\n");
	pulleyback_add (lce1, der1);
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Adding to instance #2\n");
	pulleyback_add (lce2, der2);
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Making the transactions collaborate\n");
	pulleyback_collaborate (lce1,lce2);
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Adding to instance #2 -- mouthing bad grammar\n");
	pulleyback_add (lce2, der3);
	fprintf (stderr, "Added  to instance #2 -- mouthing bad grammar\n");
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Closing PulleyBack instances #1 and #2\n");
	pulleyback_close ((void *) lce1);
	pulleyback_close ((void *) lce2);
	fprintf (stderr, "Closed PulleyBack instances #1 and #2\n");
}


// test2: lce1,lce2 each have 1 attr. break lce2. then collaborate.
void test2 (int argc, char **argv) {
	int argm = argc / 2;
	uint8_t *der_dn1 = (uint8_t *) "\x04\x1cuid=bakker,dc=orvelte,dc=nep";
	uint8_t *der_dn2 = (uint8_t *) "\x04\x1auid=smid,dc=orvelte,dc=nep";
	uint8_t *der_at1 = (uint8_t *) "\x04\x0dx . go@ gone@";
	uint8_t *der_at2 = (uint8_t *) "\x04\x19y aap@12345 . noot@ mies@";
	uint8_t *der_at3 = (uint8_t *) "\x04\x1by aap@12345 . noot@ . mies@";
	uint8_t *der1 [] = { der_dn1, der_at1 };
	uint8_t *der2 [] = { der_dn2, der_at2 };
	uint8_t *der3 [] = { der_dn2, der_at3 };
	struct lcenv *lce1, *lce2;
	lce1 = (struct lcenv *) pulleyback_open (argc-argm, argv+argm, 2);
	lce2 = (struct lcenv *) pulleyback_open (     argm, argv     , 2);
	if ((lce1 == NULL) || (lce2 == NULL)) {
		fprintf (stderr, "Failed to open Pulley Backend\n");
		exit (1);
	}
	fprintf (stderr, "Opened PulleyBack instances #1 and #2\n");
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Adding to instance #1\n");
	pulleyback_add (lce1, der1);
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Adding to instance #2\n");
	pulleyback_add (lce2, der2);
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Adding to instance #2 -- mouthing bad grammar\n");
	pulleyback_add (lce2, der3);
	fprintf (stderr, "Added  to instance #2 -- mouthing bad grammar\n");
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Making the transactions collaborate\n");
	pulleyback_collaborate (lce1,lce2);
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Closing PulleyBack instances #1 and #2\n");
	pulleyback_close ((void *) lce1);
	pulleyback_close ((void *) lce2);
	fprintf (stderr, "Closed PulleyBack instances #1 and #2\n");
}


// test3: lce1 has 1 attr, lce2 breaks.  add good to lce2. then collaborate.
void test3 (int argc, char **argv) {
	int argm = argc / 2;
	uint8_t *der_dn1 = (uint8_t *) "\x04\x1cuid=bakker,dc=orvelte,dc=nep";
	uint8_t *der_dn2 = (uint8_t *) "\x04\x1auid=smid,dc=orvelte,dc=nep";
	uint8_t *der_at1 = (uint8_t *) "\x04\x0dx . go@ gone@";
	uint8_t *der_at3 = (uint8_t *) "\x04\x19y aap@12345 . noot@ mies@";
	uint8_t *der_at2 = (uint8_t *) "\x04\x1by aap@12345 . noot@ . mies@";
	uint8_t *der1 [] = { der_dn1, der_at1 };
	uint8_t *der2 [] = { der_dn2, der_at2 };
	uint8_t *der3 [] = { der_dn2, der_at3 };
	struct lcenv *lce1, *lce2;
	lce1 = (struct lcenv *) pulleyback_open (argc-argm, argv+argm, 2);
	lce2 = (struct lcenv *) pulleyback_open (     argm, argv     , 2);
	if ((lce1 == NULL) || (lce2 == NULL)) {
		fprintf (stderr, "Failed to open Pulley Backend\n");
		exit (1);
	}
	fprintf (stderr, "Opened PulleyBack instances #1 and #2\n");
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Adding to instance #1\n");
	pulleyback_add (lce1, der1);
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Adding to instance #2 -- mouthing bad grammar\n");
	pulleyback_add (lce2, der2);
	fprintf (stderr, "Added  to instance #2 -- mouthing bad grammar\n");
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Adding to instance #2\n");
	pulleyback_add (lce2, der3);
	fprintf (stderr, "Added  to instance #2\n");
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Making the transactions collaborate\n");
	pulleyback_collaborate (lce1,lce2);
	debug_lcenv (lce1);
	debug_lcenv (lce2);
	fprintf (stderr, "Closing PulleyBack instances #1 and #2\n");
	pulleyback_close ((void *) lce1);
	pulleyback_close ((void *) lce2);
	fprintf (stderr, "Closed PulleyBack instances #1 and #2\n");
}


int main (int argc, char *argv []) {
	fprintf (stderr, "\n\n##### TEST 1: lce1++, lce2++, lce1==lce2, lce2 breaks \n\n");
	test1 (argc, argv);
	fprintf (stderr, "\n\n##### TEST 2: lce1++, lce2 breaks, lce2++, lce1==lce2n\n");
	test2 (argc, argv);
	fprintf (stderr, "\n\n##### TEST 3: lce1++, lce2 breaks, lce2++, lce1==lce2\n");
	test3 (argc, argv);
}
