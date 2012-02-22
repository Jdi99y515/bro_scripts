module DNS;

export {
    redef record Info += {
        is_external: bool &default=F;
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

    redef enum Notice::Type += {
        ## Indicates that a user is using an external DNS server
        EXTERNAL_DNS,

        ## Indicates that a user is using an external DNS server in 
        ## a foreign country.
        EXTERNAL_FOREIGN_DNS,
    };

    redef Notice::type_suppression_intervals += {
        [EXTERNAL_DNS] = 12hr,
        [EXTERNAL_FOREIGN_DNS] = 12hr,
    };

    const local_countries: set[string] = {
        "US",
    } &redef;

}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    local rec = c$dns;
    if(!rec$RD)
        return;

    local orig_h = rec$id$orig_h;
    local resp_h = rec$id$resp_h;

    #is this an outbound query
    if(!Site::is_local_addr(orig_h) || Site::is_local_addr(resp_h))
        return;

    if(orig_h in ignore_external || resp_h in ignore_external)
        return;

    rec$is_external=T;

    local loc = lookup_location(resp_h);

    rec$cc = "";
    if(loc?$country_code){
        rec$cc = loc$country_code;
    }

    when (local hostname = lookup_addr(resp_h)) {
        #Doesn't work for the log, but we can use it here :-(
        #rec$resp_h_hostname = hostname;

        local note = EXTERNAL_DNS;
        local nmsg = fmt("An external DNS server is in use %s(%s)", resp_h, hostname);

        if(rec$cc !in local_countries){
            note = EXTERNAL_FOREIGN_DNS;
            nmsg = fmt("An external foreign(%s) DNS server is in use %s(%s).", rec$cc, resp_h, hostname);
        }
        local ident = fmt("%s-%s", orig_h, resp_h);
        NOTICE([$note=note,
                $msg=nmsg,
                $sub=hostname,
                $identifier=ident,
                $conn=c]);
        
    }


}

event bro_init()
{
    Log::add_filter(DNS::LOG, [$name = "external-dns",
                                $path = "external_dns",
                                $exclude = set("uid", "proto", "trans_id","qclass", "qclass_name", "qtype", "rcode",
                                "QR","AA","TC","RD","RA","Z","answers","TTLs"),
                                $pred(rec: DNS::Info) = {

        return rec$is_external==T;
            return F;
    } ]);
}
