module DNS;

export {
    redef record Info += {
        ## Country code of external DNS server
        cc: string &log &optional;
        ## hostname of external DNS server
        #resp_h_hostname: string &log &optional;
    };


    const ignore_external: set[subnet] = {
        8.8.8.8/32, #google dns
        8.8.4.4/32, #google dns
        208.67.220.123/32, #opendns
        208.67.222.222/32, #opendns
        208.67.220.220/32, #opendns
    } &redef;

}

event bro_init()
{
    Log::add_filter(DNS::LOG, [$name = "external-dns",
                                $path = "external_dns",
                                $exclude = set("uid", "proto", "trans_id","qclass", "qclass_name", "qtype", "rcode",
                                "QR","AA","TC","RD","RA","Z","answers","TTLs"),
                                $pred(rec: DNS::Info) = {
        if(!rec$RD)
            return F;

        local orig_h = rec$id$orig_h;
        local resp_h = rec$id$resp_h;

        #is this an outbound query
        if(!Site::is_local_addr(orig_h) || Site::is_local_addr(resp_h))
            return F;

        if(orig_h in ignore_external || resp_h in ignore_external)
            return F;

        local loc = lookup_location(resp_h);

        rec$cc = "";
        if(loc?$country_code){
            rec$cc = loc$country_code;
        }
        return T;

    } ]);
}
