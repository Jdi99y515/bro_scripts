@load base/frameworks/metrics

redef enum Metrics::ID += {
    COUNTRY_CONNECTIONS
};

event bro_init()
{
    Metrics::add_filter(COUNTRY_CONNECTIONS,
                [$name="all",
                 $break_interval=600secs
                ]);
}

event connection_established(c: connection)
{
    if(Site::is_local_addr(c$id$orig_h)){
        local loc = lookup_location(c$id$resp_h);
        if(loc?$country_code) {
            local cc = loc$country_code;
            Metrics::add_data(COUNTRY_CONNECTIONS, [$str=cc], 1);
        }
    }
}
