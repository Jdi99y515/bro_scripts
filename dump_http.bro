global f: file = open("http.txt");
event bro_init()
{
    enable_raw_output(f);
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    print f, "---------------";
    print f, c$id$orig_h, c$id$resp_h, c$http;
    print f, data;
    print f, "---------------";
}
