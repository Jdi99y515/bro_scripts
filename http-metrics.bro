@load base/frameworks/metrics

redef enum Metrics::ID += {
    HTTP_METRICS,
};

event bro_init()
{
    Metrics::add_filter(HTTP_METRICS,
                [$name="all",
                 $break_interval=600secs
                ]);
}

event HTTP::log_http(rec: HTTP::Info)
{
    if(Site::is_local_addr(rec$id$resp_h)) {
        Metrics::add_data(HTTP_METRICS, [$str="server_bytes"], rec$response_body_len);
        Metrics::add_data(HTTP_METRICS, [$str="server_hits"], 1);
    } else {
        Metrics::add_data(HTTP_METRICS, [$str="client_bytes"], rec$response_body_len);
        Metrics::add_data(HTTP_METRICS, [$str="client_hits"], 1);
    }
}
