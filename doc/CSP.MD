# Communication Sequential Processes?

> *This design looks a lot like CSP or CCS.  How far is it off?*

*These are mere mesmerations.*

CSP has synchronous communication structures `c!x` and `c?v` for writing
a value `x` to a channel `c` and retrieving it in another process into
variable `v`.  The sender and recipient wait for each other, so the
communication happens in lock-step.  This makes it a bi-directional
communication structure.

In the current language, the values passed are states, not arbitrary
values like in a programming language.  This is not uncommon; values
in CSP, Pi-calculus and lambda-calculus are often the language's
primary constructs.

The communication is asynchronous in our example; an event may have
happened in the past to influence a step now.

One way where explicit sending might be helpful is to communicate to a
plugin that has been loaded under a life cycle name, but that does not
have one itself.  The logic could be to create a transient instance,
asking it to send back a response when a task has been done.

CSP also supports choice, both deterministically and non-deterministically.
The language as we describe it now does not.  If we did, we would be
defining a complete programming language and that might not be useful
if we want to retain the abstraction of just doing the synchronisation
between processes.

