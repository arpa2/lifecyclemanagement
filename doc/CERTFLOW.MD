# Certification Flow

> *Although DANE and ACME are helpful protocols, and fit for automation,
> doing this well is far from straightforward.  We invented the idea
> of Life Cycle Management to accommodate it in a live, large-scale setup.*

The process for obtaining an X.509 certificate over ACME, while keeping
the interests of DANE in mind inclusive of DNS caching behaviour and the
strong reject of anything that is off during the time, is strongly
intertwined.  The additional requirement of automatically renewing keys
and serving all certificates as soon as possible but never too early
complicates things even further.  The diagram shows the ordering relations.

![Getting that Pesky Certificate working](pix/x509-acme-dane-tlspool.png)

Arrows indicate time ordering.  The four columns are usually described in
isolation, and integrating it all is left as a gentle exercise to the
reader.  Keep in mind that errors can occur at any stage, and must be
handled with care.

The life Cycle Management system is made to define these steps, and
trigger independent processes to take a step whenever the prior actions
are completed.  The description of the diagram would be in a set of four
`lifecycleState` attribute values:

  * `x509 . keygen@ request@ acme?download certified@ dane?cached_dns public_use@ deprecated@ historic@`
  * `acme . x509?request upload@ proof_dns@ download@ removed_dns@ clean_dns@`
  * `dane . x509?certified added_dns@ cached_dns@ x509?historic removed_dns@ clean_dns@`
  * `tlspool . x509?public_use assigned_tls@ removed_tls@`

These four processes are all at the beginning, as indicated by the dot,
but only `x509` can move.  The `?` indicate the time ordering arrows that
crossover between columns; arrows within the columns are taken care of by
their individual order.


## Drivers

The four Life Cycles each start their own driver.  At each stage, they will
skip any `?` events because these will have been passed in Life Cycle
Management, as that is its responsibility.  So the first `@` event after
the dot is what a driver should look for.  Any time written there may be
assumed to have passed.  If no time is shown, processing took care as soon
as possible.

The driver can move the dot beyond this point, and perhaps further, while
annotating the time on each `@` that does not have one at the time that
the dot jumps over it.

Drivers may also learn about future timestamps, and add those to
`@` events after the dot.  An example is
[learning about DNS delays](https://github.com/arpa2/docker-demo/tree/master/demo-dns#learning-about-dns-cache-timing)
while inserting data for DANE or ACME, and setting an appropriate
time for it; this applies to `cached_dns@` and `clean_dns@`
for example and, depending on the ACME implementation, it may also
define the first certain-to-work `proof_dns@` timing.  When such times
are set, the Life Cycle Management code will be sure not to fire at
any earlier time.  Other good examples in the X.509 column are setting
`deprecated@` and `historic@` to times depending on the requests, and
later overridden by the certificates, `notBefore` and `notAfter`
attributes.


## Success and Failures

When successful, the new attribute value can be sent to LDAP as a
replacement for the old value.  This will retract the old value from
Life Cycle Management and insert the new one as though it was a fresh
new value.  Though the entire attribute value might be replaced at this
point, you should really know what you are doing if you intend to use
that.  While updating the `lifecycleState` attributes, the other
attributes in the same object in LDAP might also be changed.  This
allows for storage of intermediate results alongside the `lifecycleState`
attributes.

Failures should be handled atomically.  That is, everything succeeds
or everything fails.  So there should be no uploads, no storage used,
and so on.  The failure is not reported back to Life Cycle Management;
it will simply continue to trigger a driver with exponential fallback
until the attribute is removed from LDAP by a success.  Note that any
changes to a single LDAP object is always atomic; when you store your
data alongside the `lifecycleState` attributes you should have no
problems with an atomic implementation.

Important to realise is that these attempts must be idempotent: doing
the same thing again makes no difference.  This will often be the case
if LDAP is not updated.


## Simple and Powerful

This system appears to be (just) powerful enough to create the
kind of complex processes that seem to be required here.  In spite
of the expressive power, it is not that complex.  That's always a
winning combination.


## Accurate and Flexible

The sytem is accurate, but also flexible.  Administrators may choose
any implementation they like for the various components.  And they may
want to add or remove columns, thereby complicating or simplifying the
interdependencies.  The simple text format however, allows terse and
concise descriptions of the process to follow.

As an example, consider a self-signed certificate.  The ACME column
would be removed and another put in its place.  It will still bring
the certificate from `request` to `certified` but with other steps
in the new columns that describes self-signatures.

As another example we used a `TLS Pool` server, but that would not
be possible everywhere.  Even when the process looks the same, with
`configured` and `removed` steps, the implementation may differ.
This is easily arranged by calling on another driver, which can
implement a completely different logic.  Where it is possible, the
TLS Pool can be really helpful in automating the flow of certificates
through one's systems; it has been designed to integrate with this
kind of automation.

