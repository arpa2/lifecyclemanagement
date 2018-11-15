/* Create structures and see how they are doing.
 */


#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "lifecycle.h"


struct lcstate *new_lcstate (struct lcobject *lco, char *lcs, size_t lcslen);
void debug_lcstate (struct lcstate *lcs, char *what_to_do);

struct lcobject *new_lcobject (char *dn, size_t dnlen);
void debug_lcobject (struct lcobject *lco);



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



int main (int argc, char **argv) {
	argc = 0;
	argv = NULL;
	char *s_dn  = "uid=bakker%2bkoeken,dc=orvelte,dc=nep";
	char *s_lcs = "pkix req@56 pubkey@123 . cert@ deprecate@ expire@";
	debug ("Creating and dumping lifecycleObject");
	struct lcobject *lco = new_lcobject (     s_dn,  strlen (s_dn ));
	debug_lcobject (lco);
	debug ("Creating and dumping lifecycleState");
	struct lcstate *lcs = new_lcstate  (lco, s_lcs, strlen (s_lcs));
	debug_lcstate (lcs, NULL);
	debug ("Dumping the lifecycleObject with added lifecycleState");
	debug_lcobject (lco);
	//TODO// freeing
}

