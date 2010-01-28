function notice_exec_ipblocker(n: notice_info, a: NoticeAction): NoticeAction
{
    execute_with_notice("/usr/local/bin/bro_ipblocker_block", n);
    return NOTICE_ALARM_ALWAYS;
}

