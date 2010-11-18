#output something like this
#smtp_metrics time=1261506588.216565 total=54 inbound=49 outbound=5 inbound_err=17 outbound_err=0

@load global-ext
@load smtp-ext

export {
    global smtp_metrics: table[string] of count &default=0; #&synchronized;
    global smtp_metrics_interval = +60sec;
    const smtp_metrics_log = open_log_file("smtp-ext-metrics");
}

event smtp_write_stats()
    {
    if (smtp_metrics["total"]!=0)
        {
        print smtp_metrics_log, fmt("smtp_metrics time=%.6f total=%d inbound=%d outbound=%d inbound_err=%d outbound_err=%d",
            network_time(),
            smtp_metrics["total"],
            smtp_metrics["inbound"],
            smtp_metrics["outbound"],
            smtp_metrics["inbound_err"],
            smtp_metrics["outbound_err"]);
        clear_table(smtp_metrics);
        }
    schedule smtp_metrics_interval { smtp_write_stats() };
    }

event bro_init()
    {
    set_buf(smtp_metrics_log, F);
    schedule smtp_metrics_interval { smtp_write_stats() };
    }


event smtp_ext(id: conn_id, si: smtp_ext_session_info) &priority=-10
    {
    ++smtp_metrics["total"];
    if(is_local_addr(id$orig_h))
        {
        ++smtp_metrics["outbound"];
        if(si$last_reply!="")
            ++smtp_metrics["outbound_err"];
        }
    else
        {
        ++smtp_metrics["inbound"];
        if(si$last_reply!="")
            ++smtp_metrics["inbound_err"];
        }
    }

