@load base/frameworks/metrics

@load http-metrics

function do_metric(hostname: string, size: count)
{
    if (/youtube/ in hostname && size > 512*1024) {
        Metrics::add_data(HTTP_METRICS, [$str="youtube_bytes"], size);
        Metrics::add_data(HTTP_METRICS, [$str="youtube_views"], 1);
    }
    else if (/facebook.com|fbcdn.net/ in hostname && size > 20) {
        Metrics::add_data(HTTP_METRICS, [$str="facebook_bytes"], size);
        Metrics::add_data(HTTP_METRICS, [$str="facebook_views"], 1);
    }
    else if (/google.com/ in hostname && size > 20) {
        Metrics::add_data(HTTP_METRICS, [$str="google_bytes"], size);
        Metrics::add_data(HTTP_METRICS, [$str="google_views"], 1);
    }
    else if (/nflximg.com/ in hostname && size > 200*1024) {
        Metrics::add_data(HTTP_METRICS, [$str="netflix_bytes"], size);
        Metrics::add_data(HTTP_METRICS, [$str="netflix_views"], 1);
    }
    else if (/pandora.com/ in hostname && size > 512*1024) {
        Metrics::add_data(HTTP_METRICS, [$str="pandora_bytes"], size);
        Metrics::add_data(HTTP_METRICS, [$str="pandora_views"], 1);
    }
    else if (/gmail.com/ in hostname && size > 20) {
        Metrics::add_data(HTTP_METRICS, [$str="gmail_bytes"], size);
        Metrics::add_data(HTTP_METRICS, [$str="gmail_views"], 1);
    }
}

redef record connection += {
    resp_hostname: string &optional;
};

event ssl_established(c: connection)
{
    if(c?$ssl && c$ssl?$server_name) {
        c$resp_hostname = c$ssl$server_name;
    }
}

event connection_finished(c: connection)
{
    if (c?$resp_hostname)
        do_metric(c$resp_hostname, c$resp$num_bytes_ip);
}

event HTTP::log_http(rec: HTTP::Info)
{
    if(rec?$host)
        do_metric(rec$host, rec$response_body_len);
}
