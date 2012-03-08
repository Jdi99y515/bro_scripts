module Notice;

export {
    redef enum Action += {
        ## Indicates that the notice should be sent to ipblocker to block
        ACTION_IPBLOCKER
    };
}

event notice(n: Notice::Info) &priority=-5
{
    if (ACTION_IPBLOCKER !in n$actions)
        return;
    local id = n$id;
    
    # The IP to block is whichever one is not the local address.
    if(Site::is_local_addr(id$orig_h))
        local ip = id$resp_h;
    else
        local ip = id$orig_h;

    local cmd = fmt("/usr/local/bin/bro_ipblocker_block %s", ip);
    execute_with_notice(cmd, n);
}
