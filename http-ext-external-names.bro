@load http-ext

module HTTP;

export {
    const local_domains = /(^|\.)example\.com($|:)/ &redef;

    # in site policy, redef HTTP::ignore_external_addr += {1.2.3.4};
    #                 redef HTTP::ignore_external_host += {"www.foo.com"};


    global ignore_external_addr: set[addr]   &redef;
    global ignore_external_host: set[string] &redef;
}

event http_ext(id: conn_id, si: http_ext_session_info) &priority=1
{
    if(id$resp_h in ignore_external_addr || si$host in ignore_external_host)
        return;

    if(is_local_addr(id$resp_h) && local_domains !in si$host) {
        si$force_log = T;
        add si$force_log_reasons["external_name"];
    }
}
