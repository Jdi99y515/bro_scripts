module Notice;

export {
    redef enum Action += {
        ## Indicates that the notice should be sent to ipblocker to block
        ACTION_IPBLOCKER
    };
    const ipblocker_types: set[Notice::Type] = {} &redef;
    ## Add a helper to the notice policy for blocking addresses
    redef Notice::policy += {
            [$pred(n: Notice::Info) = { return (n$note in Notice::ipblocker_types); },
             $action = ACTION_IPBLOCKER,
             $priority = 10],
    };
}

event notice(n: Notice::Info) &priority=-5
{
    if (ACTION_IPBLOCKER !in n$actions)
        return;
    local id = n$id;
    
    # The IP to block is whichever one is not the local address.
    local ip: addr;
    if(Site::is_local_addr(id$orig_h))
        ip = id$resp_h;
    else
        ip = id$orig_h;

    local cmd = fmt("/usr/local/bin/bro_ipblocker_block %s", ip);
    execute_with_notice(cmd, n);
}
