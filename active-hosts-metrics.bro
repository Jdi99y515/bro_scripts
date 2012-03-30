module Active;
@load base/frameworks/metrics


export {
    const host_tracking = LOCAL_HOSTS &redef;
}

event bro_init()
{
    Metrics::add_filter("active",
                [$name="all",
                 $break_interval=3600secs
                ]);
}

event connection_established(c: connection)
{
    #taken from known-hosts.bro
    #I don't want to count incoming scans or anything, so just count outgoing conns.
    local host = c$id$orig_h;
    if ( c$orig$state == TCP_ESTABLISHED &&
         c$resp$state == TCP_ESTABLISHED &&
         addr_matches_host(host, host_tracking) )
    {
        Metrics::add_unique("active", [$str="hosts"], cat(host));
    }
}
