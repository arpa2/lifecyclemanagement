/* Call this program with any number of test strings to test grammar of the
 * lifecycleState attribute.  A preceding character predicts whether there
 * should be success; 1 predicts OK and 0 predicts STXERR.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include "../src/lifecycle.h"


bool grammar_lcstate (char *lcs);


int main (int argc, char **argv) {
	int argi;
	bool failed = false;
	for (argi=1; argi<argc; argi++) {
		bool expect = ('1' == argv [argi][0]);
		if (grammar_lcstate (&argv [argi][1]) != expect) {
			fprintf (stderr, "Expected %s: %s\n",
				expect ? "OK" : "STXERR",
				argv [argi]);
			failed = true;
		}
	}
	exit (failed ? 1 : 0);
}

