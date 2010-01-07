@load global-ext
@load smtp-ext

module PHISH;

global smtp_password_conns: set[conn_id] &read_expire=2mins;


export {
    redef enum Notice += {
        SMTP_PossiblePWPhish,
        SMTP_PossiblePWPhishReply,
    };
    global phishing_counter: table[string] of count &default=0 &write_expire=1hr &synchronized;
    global phishing_reply_tos: set[string] &synchronized &redef;
    global phishing_threshold = 50;
}


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

event bro_done()
{
    print "Counter";
    print phishing_counter;
    print "bad reply-tos";
    print phishing_reply_tos;
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
    if(is_local_addr(id$orig_h)) {
        for (to in si$rcptto){
            if(to in phishing_reply_tos){
                NOTICE([$note=SMTP_PossiblePWPhishReply,
                        $msg=fmt("%s replied to %s", si$mailfrom, to),
                        $sub=si$mailfrom
                      ]);
            }
        }
    } else {
        if (id !in smtp_password_conns)
            return;
        if(++(phishing_counter[si$mailfrom]) > phishing_threshold){
            if(si$reply_to != "")
                add phishing_reply_tos[si$reply_to];
            else 
                add phishing_reply_tos[si$mailfrom];
            NOTICE([$note=SMTP_PossiblePWPhish,
                    $msg=fmt("%s(%s) may be phishing", si$mailfrom, si$reply_to),
                    $sub=si$mailfrom
                  ]);
        }

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

}
