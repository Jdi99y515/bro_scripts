global f: file = open("http.txt");
event bro_init()
{
    enable_raw_output(f);
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    print f, "---------------\n";
    print f, fmt("%s %s %s %s %s\n", c$id$orig_h, c$id$resp_h, c$http$host, c$http$uri, c$http);
    print f, data;
    print f, "---------------\n";
}
