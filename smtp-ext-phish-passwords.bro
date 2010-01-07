@load global-ext
@load smtp-ext

global smtp_password_conns: set[conn_id] &read_expire=2mins;

event bro_init()
{
    LOG::create_logs("password-mail", All, F, T);
    LOG::define_header("password-mail", cat_sep("\t", "", 
                                          "ts",
                                          "orig_h", "orig_p",
                                          "resp_h", "resp_p",
                                          "helo", "message-id", "in-reply-to", 
                                          "mailfrom", "rcptto",
                                          "date", "from", "reply_to", "to",
                                          "files", "last_reply", "x-originating-ip",
                                          "path", "is_webmail", "agent"));
}


event smtp_data(c: connection, is_orig: bool, data: string)
{
    if(is_local_addr(c$id$orig_h))
        return;
    # look for 'password'
    if(/[pP][aA][sS][sS][wW][oO][rR][dD]/ in data)
        add smtp_password_conns[c$id];
}

event smtp_ext(id: conn_id, si: smtp_ext_session_info)
{
    if(is_local_addr(id$orig_h))
        return;
    if (id !in smtp_password_conns)
        return;
    local log = LOG::get_file_by_id("password-mail", id, F);
    print log, cat_sep("\t", "\\N",
                network_time(),
                id$orig_h, port_to_count(id$orig_p), id$resp_h, port_to_count(id$resp_p),
                si$helo,
                si$msg_id,
                si$in_reply_to,
                si$mailfrom,
                fmt_str_set(si$rcptto, /["'<>]|([[:blank:]].*$)/),
                si$date, 
                si$from, 
                si$reply_to, 
                fmt_str_set(si$to, /["']/),
                fmt_str_set(si$files, /["']/),
                si$last_reply, 
                si$x_originating_ip,
                si$path,
                si$is_webmail,
                si$agent);

}
