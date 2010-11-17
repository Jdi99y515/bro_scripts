#output something like this
#http_metrics total=343243 inbound=102313 outbound=3423432 exe_download=23

@load global-ext
@load http-ext

export {
    global http_metrics: table[string] of count &default=0 &synchronized;
    global http_metrics_interval = +60sec;
    const http_metrics_log = open_log_file("http-ext-metrics");
}

event http_write_stats()
    {
    if (http_metrics["total"]!=0)
        {
        print http_metrics_log, fmt("http_metrics time=%.6f total=%d inbound=%d outbound=%d video_download=%d youtube_watches=%d",
            network_time(),
            http_metrics["total"],
            http_metrics["inbound"],
            http_metrics["outbound"],
            http_metrics["video_download"],
            http_metrics["youtube_watches"]
            );
        clear_table(http_metrics);
        }
    schedule http_metrics_interval { http_write_stats() };
    }

event bro_init()
    {
    set_buf(http_metrics_log, F);
    schedule http_metrics_interval { http_write_stats() };
    }


event http_ext(id: conn_id, si: http_ext_session_info) &priority=-10
    {
    ++http_metrics["total"];
    if(is_local_addr(id$orig_h))
        ++http_metrics["outbound"];
    else
        ++http_metrics["inbound"];

    if (/\.(avi|flv|mp4|mpg)/ in si$uri)
        ++http_metrics["video_download"];
    if (/watch\?v=/ in si$uri && /youtube/ in si$host)
        ++http_metrics["youtube_watches"];

    }
