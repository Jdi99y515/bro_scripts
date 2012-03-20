module Active;
@load base/frameworks/metrics

redef enum Metrics::ID += {
    ACTIVE_HOSTS,
};

export {
    global active_hosts: set[addr] &create_expire=1hr &synchronized &redef;
    const host_tracking = LOCAL_HOSTS &redef;
}

event bro_init()
{
    Metrics::add_filter(ACTIVE_HOSTS,
                [$name="all",
                 $break_interval=3600secs
                ]);
}

event connection_established(c: connection)
{
    #taken from known-hosts.bro
    #I don't want to count incoming scans or anything, so just count outgoing conns.
    local host = c$id$orig_h;
    if ( host !in active_hosts && 
         c$orig$state == TCP_ESTABLISHED &&
         c$resp$state == TCP_ESTABLISHED &&
         addr_matches_host(host, host_tracking) )
    {
        add active_hosts[host];
        Metrics::add_data(ACTIVE_HOSTS, [$str="hosts"], 1);
    }
}
