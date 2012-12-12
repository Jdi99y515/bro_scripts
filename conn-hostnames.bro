@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssl
@load base/utils/site

module Conn;

event connection_established(c: connection)
{
    Conn::set_conn(c, F);
}

redef record Conn::Info += {
    resp_hostname: string &optional &log;
};

event http_header (c: connection, is_orig: bool, name: string, value: string)
{
    if(name == "HOST") {
        c$conn$resp_hostname = value;
        print "set hostname", value;
        flush_all();
    }
}

event ssl_established(c: connection)
{
    if(c?$ssl && c$ssl?$server_name) {
        c$conn$resp_hostname = c$ssl$server_name;
        print "set hostname", c$ssl$server_name;
        flush_all();
    }
}

event bro_init()
{
    Log::add_filter(Conn::LOG, [$name = "conn-hostnames",
                                $path = "conn_hostnames",
                                $pred(rec: Conn::Info) = {
        return (rec?$resp_hostname);
    }]);
}
