@load base/frameworks/metrics

redef enum Metrics::ID += {
    HTTP_YOUTUBE_METRICS,
};

event bro_init()
{
    Metrics::add_filter(HTTP_YOUTUBE_METRICS,
                [$name="all",
                 $break_interval=600secs
                ]);
}

event HTTP::log_http(rec: HTTP::Info)
{
    if (rec?$host && /youtube/ in rec$host && rec$response_body_len > 1024*1024) {
        Metrics::add_data(HTTP_YOUTUBE_METRICS, [$str="bytes"], rec$response_body_len);
        Metrics::add_data(HTTP_YOUTUBE_METRICS, [$str="views"], 1);
    }
}
