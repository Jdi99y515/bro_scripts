@load my-notice-action-filter
global subnet_admins: table[subnet] of string &redef;

function notice_email_subnet_admins(n: notice_info, a: NoticeAction): NoticeAction
{
    local id = n$id;
    local host = is_local_addr(id$orig_h) ? id$orig_h : id$resp_h;
    local admin = "";

    if(host !in subnet_admins)
        admin = mail_dest;
    else
        admin = subnet_admins[host];
    email_notice_to(n, admin);
    event notice_alarm(n, NOTICE_EMAIL);
    return NOTICE_FILE;
}

function notice_email_subnet_admins_then_tally(n: notice_info, a: NoticeAction): NoticeAction
{
    a = notice_email_then_tally(n, a);
    if(a == NOTICE_EMAIL){
        a = notice_email_subnet_admins(n, a);
    }
    return a;
}
