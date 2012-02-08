@load base/frameworks/metrics

redef enum Metrics::ID += {
    HTTP_MIME_METRICS,
};

event bro_init()
{
    Metrics::add_filter(HTTP_MIME_METRICS,
                [$name="all",
                 $break_interval=3600secs
                ]);
}

event HTTP::log_http(rec: HTTP::Info)
{
    if(Site::is_local_addr(rec$id$resp_h) && rec?$mime_type) {
        Metrics::add_data(HTTP_MIME_METRICS, [$str=rec$mime_type], rec$response_body_len);
    }
}
