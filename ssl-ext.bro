@load global-ext
@load ssl

module SSL_KnownCerts;

export {
	const local_domains = /(^|\.)(osu|ohio-state)\.edu$/ |
	                      /(^|\.)akamai(tech)?\.net$/ &redef;

	# The list of all detected certs.  This prevents over-logging.
	global certs: set[addr, port, string] &create_expire=1day &synchronized;
	
	# The hosts that should be logged.
	const split_log_file = F &redef;
	const logged_hosts = LocalHosts &redef;

	redef enum Notice += {
		# Raised when a non-local name is found in the CN of a SSL cert served
		# up from a local system.
		SSLExternalName,
		};
}

event bro_init()
{
    LOG::create_logs("ssl-known-certs", All, split_log_file, T);
    LOG::define_header("ssl-known-certs", cat_sep("\t", "\\N", "resp_h", "resp_p", "subject"));
}


event ssl_certificate(c: connection, cert: X509, is_server: bool)
	{
	# The ssl analyzer doesn't do this yet, so let's do it here.
	#add c$service["SSL"];
	event protocol_confirmation(c, ANALYZER_SSL, 0);
	
	if ( !addr_matches_hosts(c$id$resp_h, logged_hosts) )
		return;
	
	lookup_ssl_conn(c, "ssl_certificate", T);
	local conn = ssl_connections[c$id];
	if ( [c$id$resp_h, c$id$resp_p, cert$subject] !in certs )
		{
		add certs[c$id$resp_h, c$id$resp_p, cert$subject];
		local log = LOG::get_file_by_id("ssl-known-certs", c$id, F);
		print log, cat_sep("\t", "\\N", c$id$resp_h, fmt("%d", c$id$resp_p), cert$subject);

	    if(is_local_addr(c$id$resp_h))
	        {
	        local parts = split_all(cert$subject, /CN=[^\/]+/);
	        if (|parts| == 3)
	            {
	            local cn = parts[2];
	            if (local_domains !in cn)
	                {
	                NOTICE([$note=SSLExternalName,
	                        $msg=fmt("SSL Cert for %s returned from an internal host - %s", cn, c$id$resp_h),
	                        $conn=c]);
	                }
	            }
	        }
	    }
	}

