event bro_init()
{
    Log::add_filter(HTTP::LOG, [$name = "http-sqli",
                                $path = "http_sqli",
                                $pred(rec: HTTP::Info) = { return HTTP::URI_SQLI in rec$tags ; }
                                ]);
}
