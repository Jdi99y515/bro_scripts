@load http-ext
@load ipblocker

module HTTP;

export {
    redef enum Notice += {
        HTTP_IncorrectFileTypeBadHost
    };
}

redef notice_action_filters += {
    [HTTP_IncorrectFileTypeBadHost] = notice_exec_ipblocker_dest,
};

event http_ext(id: conn_id, si: http_ext_session_info) &priority=1
{
    if(is_local_addr(id$resp_h))
        return;
    if(! ("identified-files" in si$tags && si$mime_type == "application/x-dosexec"))
        return;

    if(/co.cc/ in si$host) {
        NOTICE([$note=HTTP_IncorrectFileTypeBadHost,
                $id=id,
                $msg=fmt("EXE Downloaded from bad host %s %s %s", id$orig_h, id$resp_h, si$url),
                $sub="http-ext"
            ]);
        }
}
