@load global-ext
@load http-ext

const stdout = open_log_file("http-requests") &raw_output;

event http_ext(id: conn_id, si: http_ext_session_info)
{
    print stdout, cat_sep("\t", "\\N",
                          si$start_time,
                          id$orig_h, port_to_count(id$orig_p),
                          id$resp_h, port_to_count(id$resp_p),
                          si$method, si$url, si$referrer,
                          si$user_agent, si$proxied_for);
}
