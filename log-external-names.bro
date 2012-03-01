event bro_init()
{
    Log::add_filter(HTTP::LOG, [$name = "http-external",
                                $path = "http_external",
                                $pred(rec: HTTP::Info) = { return Site::is_local_addr(rec$id$resp_h) && rec?$host && !Site::is_local_name(rec$host); }
                                ]);
}
