# $Id$
@load notice
global rdp_connection: event(c: connection);

module RDP;

@load signatures
redef signature_files += "rdp.sig";
redef signature_actions += { ["dpd_rdp"] = SIG_IGNORE };


global rdp_ports = {
	3389/tcp
};
redef capture_filters += { ["rfb"] = "tcp and port 3389"};

event signature_match(state: signature_state, msg: string, data: string)
{
    if (state$id == "dpd_rdp"){
		add state$conn$service["RDP"];
        event rdp_connection(state$conn);
    }
}
