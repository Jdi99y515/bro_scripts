@load base/frameworks/notice
@load base/protocols/http

export {
	redef enum Notice::Type += { 
		Rogue_Access_Point
	};

    const mobile_browsers =
        /i(Phone|Pod|Pad)/ |
        /Android/ &redef;

    const wireless_nets: set[subnet] &redef;
    global rogue_access_points : set[addr] &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=2
{
    if (!is_orig )
        return;
    local ip = c$id$orig_h;

    if (!Site::is_local_addr(ip) || ip in wireless_nets || ip in rogue_access_points)
        return;

    if ( name == "USER-AGENT" && mobile_browsers in value){
        local message = "Rogue access point detected";
        local submessage = value;
        NOTICE([$note=Rogue_Access_Point, $msg=message, $sub=submessage,
                $id=c$id]);
        add rogue_access_points[ip];
    }
}
