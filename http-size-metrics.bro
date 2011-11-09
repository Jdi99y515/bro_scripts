@load base/frameworks/metrics
@load base/protocols/http
@load base/utils/site

redef enum Metrics::ID += {
	HTTP_REQUEST_SIZE_BY_HOST,
};

event bro_init()
{
    Metrics::add_filter(HTTP_REQUEST_SIZE_BY_HOST,
                [$name="all",
                 $break_interval=3600secs
                ]);

}

event HTTP::log_http(rec: HTTP::Info)
{
	if ( rec?$host && rec?$response_body_len)
		Metrics::add_data(HTTP_REQUEST_SIZE_BY_HOST, [$str=rec$host], rec$response_body_len);
}
