@load base/frameworks/metrics

event bro_init()
{
    Metrics::add_filter("http.mime",
                [$name="all",
                 $break_interval=600secs
                ]);
}

event HTTP::log_http(rec: HTTP::Info)
{
    if(Site::is_local_addr(rec$id$orig_h) && rec?$mime_type) {
        Metrics::add_data("http.mime", [$str=rec$mime_type], rec$response_body_len);
    }
}
