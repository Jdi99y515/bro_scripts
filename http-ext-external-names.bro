@load http-ext

module HTTP;

export {
    const local_domains = /(^|\.)albany\.edu($|:)/ &redef;
}

event http_ext(id: conn_id, si: http_ext_session_info) &priority=10
{
    if(is_local_addr(id$resp_h) && local_domains !in si$host) {
        si$force_log = T;
        add si$force_log_reasons["external_name"];
    }
}
