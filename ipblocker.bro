function notice_exec_ipblocker(n: notice_info, a: NoticeAction): NoticeAction
{
    local cmd = fmt("lckdo /tmp/bro_ipblocker_%s /usr/local/bin/bro_ipblocker_block", n$id$orig_h);
    execute_with_notice(cmd, n);
    email_notice_to(n, mail_dest);
    return NOTICE_ALARM_ALWAYS;
}

