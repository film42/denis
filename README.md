DENIS
=====

I'm trying to take some time on vacation to learn how to make a round trip DNS request using
some cached RFCs I saved before turning my wifi off. My vacation spot has _some_ internet but
my laptop will only be able to connect to the gateway which of course has a DNS server, so I
will be testing against it.


### Running

```
cargo run -- MX google.com
```

It can handle the following response types: `A`, `AAAA`, `MX`, `SOA`. New types are very easy
to add.
