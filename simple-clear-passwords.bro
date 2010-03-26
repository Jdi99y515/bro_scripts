global clear_log_file = open_log_file("clear-password-users") &raw_output;

redef capture_filters += { ["pop3"] = "port 110" };

global pop3_ports = { 110/tcp } &redef;
redef dpd_config += { [ANALYZER_POP3] = [$ports = pop3_ports] };

event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
{
}


event pop3_login_success(c: connection, is_orig: bool,
                                user: string, password: string)
{
    if(is_local_addr(c$id$orig_h))
        return;
    print clear_log_file, cat_sep("\t", "\\N",
        network_time(),
        c$id$orig_h,
        c$id$resp_h,
        port_to_count(c$id$resp_p),
        "success",
        user);
}


event pop3_login_failure(c: connection, is_orig: bool,
                                user: string, password: string)
{
    if(!is_local_addr(c$id$orig_h))
        return;
    print clear_log_file, cat_sep("\t", "\\N",
        network_time(),
        c$id$orig_h,
        c$id$resp_h,
        port_to_count(c$id$resp_p),
        "failure",
        user);
}
