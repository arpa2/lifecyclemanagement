# Life Cycle Management

> *This is a plugin for SteamWorks Pulley, a so-called "pulleyback" module.
> Its task is to process attributes that indicate life cycle state, to
> evolve them as time and other life cycles evolve, and signal an external
> program to make steps forward.*

The management of keys is inherently complex, except on a small or manual
scale.  As soon as you scale up, you want to automate.  At that time, the
entanglements of procedures for DANE, ACME, DNS caches and internal service
setups can be incredibly difficult.

Life Cycle Management was created to solve that line of problems.  It
expresses the processes for the various aspects of key management as
sequential processes with a bit of synchronisation from time to time.
These processes are aware of time, and can express things like DNS delays.

As long as the synchronisation points are well-defined and the application
takes good care of things like
[DNS cache update delays](https://github.com/arpa2/docker-demo/tree/master/demo-dns),
the result would be a robust system for generating, sharing and updating
public credentials.


## Storage in LDAP

Attributes named `lifecycleState` can be attached to any `lifecycleObject`
in LDAP to capture one sequential progression.  Using the
[SteamWorks](https://github.com/arpa2/steamworks)
subscriber module named
[Pulley](https://github.com/arpa2/steamworks/blob/master/docs/pulley.md)
for which the Life Cycle Management system is a mere
[PulleyBack module](https://github.com/arpa2/steamworks/blob/master/docs/pulleyback-api.md)
that processes added and removed `lifecycleState` attributes.

LDAP guarantees atomic updates of individual objects.  This is why
it is useful to add `lifecycleState` attributes to the data being
managed, and to keep the data in that object.  That allows the
update of both data and `lifecycleState` at the same time.  LDAP is
perfectly suited for such combined data objects.

The configuration of Pulley is done in a so-called
[PulleyScript](http://steamworks.arpa2.net/intuition.html)
that delivers any changes to an output driver.

## Triggering Actions

The PulleyScript is configured with output drivers.  For
Life Cycle Management, these drivers will be sent two bits
of information, namely an object's `distinguishedName` and
the respective `lifecycleState` that has changed.

The output drivers can configure different life cycle names,
and run a shell command for each (through `sh -c`) by saying
things like

```
dn,lcs -> lifecycle (x509="/bin/do_x509.sh", dane="/bin/do_dane.py")
```

The `x509` and `dane` names are life cycle names, and would be
covered by the first word in `lcs`, as that is the name of the
life cycle represented in that `lifecycleState` attribute.
The paths that follow indicate the shell command to start.
These commands read sets of two lines at once; the first is to
hold the `dn` value, the second the `lcs` value.

Other than this, the programs can do anything.  They can be
made in any language.  But in any case, they are suggested
to make changes to update the object indicated by the `dn`
to demonstrate progress, specifically the `lcs` value should
be updated (as it contains a `.` to split past and future,
and that should be moved forward).  If left without update,
the request will be repeated with exponential fallback.

As a tip, an easy mechanism for updating LDAP may be the
[Crank](https://github.com/arpa2/steamworks/blob/master/docs/crank.md)
because of its FastCGI interface that can be addressed
directly or through any supporting web server.


## Example Pulley Script: X.509 Certificates

**TODO**


## Example Flow: X.509 with DANE and ACME

**TODO**

