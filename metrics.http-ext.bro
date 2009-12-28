#output something like this
#http_metrics total=343243 inbound=102313 outbound=3423432 exe_download=23

@load global-ext
@load http-ext

module HTTP;

export {
    global http_metrics: table[string] of count &default=0;
    global http_metrics_interval = +2sec;
}

event write_stats()
    {
    if (http_metrics["total"]!=0)
        {
        print fmt("http_metrics time=%.6f total=%d inbound=%d outbound=%d exe_download=%d",
            network_time(),
            http_metrics["total"],
            http_metrics["inbound"],
            http_metrics["outbound"],
            http_metrics["exe_download"]);
        clear_table(http_metrics);
        }
    schedule http_metrics_interval { write_stats() };
    }

event bro_init()
    {
    LOG::create_logs("http-ext-metrics", All, F, T);
    schedule http_metrics_interval { write_stats() };
    }


event http_ext(id: conn_id, si: http_ext_session_info) &priority=-10
    {
    ++http_metrics["total"];
    if(is_local_addr(id$orig_h))
        ++http_metrics["outbound"];
    else
        ++http_metrics["inbound"];

    if (/\.exe/ in si$uri)
        ++http_metrics["exe_download"];
    }

