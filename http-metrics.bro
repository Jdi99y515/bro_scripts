@load base/frameworks/metrics

event bro_init()
{
    Metrics::add_filter("http",
                [$name="all",
                 $break_interval=600secs
                ]);
}

event HTTP::log_http(rec: HTTP::Info)
{
    if(Site::is_local_addr(rec$id$resp_h)) {
        Metrics::add_data("http", [$str="server_bytes"], rec$response_body_len);
        Metrics::add_data("http", [$str="server_hits"], 1);
    } else {
        Metrics::add_data("http", [$str="client_bytes"], rec$response_body_len);
        Metrics::add_data("http", [$str="client_hits"], 1);
    }
}
