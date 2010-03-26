redef capture_filters += { ["pop3"] = "port 110" };

global pop3_ports = { 110/tcp } &redef;
redef dpd_config += { [ANALYZER_POP3] = [$ports = pop3_ports] };

module ClearPasswords;

export {
    global clear_log_file = open_log_file("clear-password-users") &raw_output;
    global seen_clear_users: set[addr, string] &create_expire=1day &synchronized &persistent;
}



event pop3_request(c: connection, is_orig: bool, command: string, arg: string)
{
}

function log_clear_pw(c: connection, status: string, user: string)
{
    if(is_local_addr(c$id$orig_h))
        return;
    if([c$id$orig_h, user] in seen_clear_users)
        return;
    add seen_clear_users[c$id$orig_h, user];

    local loc = lookup_location(c$id$orig_h);
    when( local hostname = lookup_addr(c$id$orig_h) ){
        print clear_log_file, cat_sep("\t", "\\N",
            network_time(),
            c$id$orig_h,
            c$id$resp_h,
            port_to_count(c$id$resp_p),
            hostname,
            loc$country_code,
            loc$region,
            "success",
            user);
    }

}

event pop3_login_success(c: connection, is_orig: bool,
                                user: string, password: string)
{
    log_clear_pw(c, "success", user);
}


event pop3_login_failure(c: connection, is_orig: bool,
                                user: string, password: string)
{
    log_clear_pw(c, "failure", user);
}
