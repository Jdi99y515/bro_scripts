@load base/frameworks/metrics
@load base/protocols/http
@load base/protocols/ssl
@load base/utils/site

redef enum Metrics::ID += {
	HTTP_REQUEST_SIZE_BY_HOST,
};

redef record connection += {
    resp_hostname: string &optional;
};

event bro_init()
{
    Metrics::add_filter(HTTP_REQUEST_SIZE_BY_HOST,
                [$name="all",
                 $break_interval=3600secs
                ]);

}


event connection_finished(c: connection)
{
    if (c?$resp_hostname) {
        local size = c$orig$size + c$resp$size;
        Metrics::add_data(HTTP_REQUEST_SIZE_BY_HOST, [$str=c$resp_hostname], size);
    }
}

event http_header (c: connection, is_orig: bool, name: string, value: string)
{
    if(name == "HOST") {
        c$resp_hostname = value;
    }
}

event ssl_established(c: connection)
{
    if(c?$ssl && c$ssl?$server_name) {
        c$resp_hostname = c$ssl$server_name;
    }
}

