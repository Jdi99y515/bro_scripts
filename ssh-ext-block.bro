@load global-ext
@load ssh-ext
@load subnet-helper
@load notice

module SSH;

export {
    global ssh_attacked: table[addr] of addr_set &create_expire=30mins;# default isn't working &default=function(a:addr):addr_set { print a;return set();};
    global libssh_scanners: set[addr] &read_expire=1hr;
    const subnet_threshold = 3 &redef;

    redef enum Notice += {
        SSH_Libssh_Scanner,
    };
}

function notice_exec_test(n: notice_info, a: NoticeAction): NoticeAction
{
    #execute_with_notice("/usr/local/bin/bro_ipblocker_block", n);
    execute_with_notice("/tmp/test", n);
    return NOTICE_ALARM_ALWAYS;
}

redef notice_action_filters += {
    [SSH_Libssh_Scanner] = notice_exec_test,
};


event ssh_ext(id: conn_id, si: ssh_ext_session_info) &priority=-10
{
    if(is_local_addr(id$orig_h)  ||
       /libssh/ !in si$client    ||
       si$status == "success")
        return;

    local subnets = add_attack(ssh_attacked, id$orig_h, id$resp_h);
    print fmt("%s scanned %d subnets", id$orig_h, subnets);
    
    if(subnets >= subnet_threshold && id$orig_h !in libssh_scanners){
        add libssh_scanners[id$orig_h];

        NOTICE([$note=SSH_Libssh_Scanner,
                $id=id,
                $msg=fmt("SSH libssh scanning. %s scanned %d subnets", id$orig_h, subnets),
                $sub="ssh-ext",
                $n=subnets]);
    }

}
