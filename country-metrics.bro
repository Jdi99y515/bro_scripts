@load base/frameworks/metrics

event bro_init()
{
    Metrics::add_filter("country.connections",
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
            Metrics::add_data("country.connections", [$str=cc], 1);
        }
    }
}
