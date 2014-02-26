module Notice;


global tmp_notice_storage_ipb: table[string] of Notice::Info &create_expire=Notice::max_email_delay+10secs;

export {
    redef enum Action += {
        ## Indicates that the notice should be sent to ipblocker to block
        ACTION_IPBLOCKER
    };
    const ipblocker_types: set[Notice::Type] = {} &redef;
}

hook Notice::policy(n: Notice::Info)
{
    if( n$note !in ipblocker_types)
        return;

    if (Site::is_local_addr(n$src))
        return;
    
    local cmd = "/usr/local/bin/bro_ipblocker_block";

    local uid = unique_id("");
    local output = "";
    tmp_notice_storage_ipb[uid] = n;

    local stdin = string_cat(cat(n$src), "\n", cat(n$note), "\n", n$msg, "\n", n$sub, "\n");
    when (local res = Exec::run([$cmd=cmd, $stdin=stdin])){
        if(res?$stdout) {
            output = string_cat("IPBlocker result:\n", join_string_vec(res$stdout, "\n"),"\n");
            tmp_notice_storage_ipb[uid]$email_body_sections[|tmp_notice_storage_ipb[uid]$email_body_sections|] = output;
        }
        if(res?$stderr) {
            output = string_cat("Ipblocker errors:\n", join_string_vec(res$stderr, "\n"),"\n");
            tmp_notice_storage_ipb[uid]$email_body_sections[|tmp_notice_storage_ipb[uid]$email_body_sections|] = output;
        }
        delete tmp_notice_storage_ipb[uid]$email_delay_tokens["ipb"];
    }
}
