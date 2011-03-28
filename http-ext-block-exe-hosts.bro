@load http-ext
@load ipblocker

module HTTP;

export {
    redef enum Notice += {
        HTTP_IncorrectFileTypeBadHost
    };

    const bad_exec_domains = 
        /co\.cc/
      | /cx\.cc/
      | /cz\.cc/
        &redef;

    const bad_exec_urls = 
        /php.adv=/
      | /http:\/\/[0-9]{1,3}\.[0-9]{1,3}.*\/index\.php\?[^=]+=[^=]+$/ #try to match http://1.2.3.4/index.php?foo=bar
        &redef;

    const bad_user_agents = 
        /Java\/1/
        &redef;

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

    if( (bad_exec_domains in si$host || bad_exec_urls in si$url)
      ||(/\.exe/ !in si$url && bad_user_agents in si$user_agent)) {
        NOTICE([$note=HTTP_IncorrectFileTypeBadHost,
                $id=id,
                $msg=fmt("EXE Downloaded from bad host %s %s %s", id$orig_h, id$resp_h, si$url),
                $sub="http-ext"
            ]);
        }
}
