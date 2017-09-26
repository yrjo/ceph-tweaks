vcl 4.0;

import std;
import directors;

acl purge {
    "::1";
    "127.0.0.1";
}

backend rgw1 {
    .host = "rgw1";
    .port = "7480";
    .connect_timeout = 5s;
    .first_byte_timeout = 15s;
    .between_bytes_timeout = 5s;
    .probe = {
        .timeout   = 30s;
        .interval  = 3s;
        .window    = 10;
        .threshold = 3;
        .request =
            "GET / HTTP/1.1"
            "Host: localhost"
            "User-Agent: Varnish-health-check"
            "Connection: close";
    }
}

backend rgw2 {
    .host = "rgw2";
    .port = "7480";
    .connect_timeout = 5s;
    .first_byte_timeout = 15s;
    .between_bytes_timeout = 5s;
    .probe = {
        .timeout   = 30s;
        .interval  = 3s;
        .window    = 10;
        .threshold = 3;
        .request =
            "GET / HTTP/1.1"
            "Host: localhost"
            "User-Agent: Varnish-health-check"
            "Connection: close";
    }
}


sub vcl_init {
    new rgw = directors.round_robin();
    rgw.add_backend(rgw1);
    rgw.add_backend(rgw2);

}

sub vcl_recv {
    set req.backend_hint = rgw.backend();

    /* Various logging for Logstash parsing using varnishncsa */
    std.log("authorization:no");

    /*
     Determine of the request came in via port 6081
     Hitch (TLS proxy) will send requests to this port
     and thus we know it is a HTTPs request
    */
    if (std.port(local.ip) == 6081) {
        std.log("proto:https");
    } else {
        std.log("proto:http");
    }

    if (req.method == "PURGE") {
        if (client.ip !~ purge) {
            return(synth(403, "Forbidden"));
        }

        ban("obj.http.x-bucket ~ " + req.http.x-bucket + " && obj.http.x-url ~ " + req.url);

        return(synth(200, "Purged"));
    }

    set req.http.host = std.tolower(req.http.host);
    set req.http.X-Forwarded-For = client.ip;

    /* We only deal with these types of HTTP request, we can block the rest */
    if (req.method != "GET" &&
       req.method != "HEAD" &&
       req.method != "PUT" &&
       req.method != "POST" &&
       req.method != "OPTIONS" &&
       req.method != "DELETE") {
        return (synth(400, "Bad Request"));
    }

    /* Remove not used incoming headers */
    unset req.http.Cookie;
    unset req.http.DNT;
    unset req.http.User-Agent;
    unset req.http.Referer;

    /* Determine if this is a authorized client or not */
    if (req.http.Authorization || req.url ~ "AWSAccessKeyId") {
        std.log("authorization:yes");
        return (pass);
    }

    /* If a non GET or HEAD request is send without Authorization we block it */
    if (req.method != "GET" && req.method != "HEAD") {
        return (synth(403, "Forbidden without proper Authorization"));
    }

    return (hash);
}

sub vcl_hit {
    if (obj.ttl >= 0s) {
        return (deliver);
    }

    if (std.healthy(req.backend_hint) && req.restarts == 0) {
        if (obj.ttl + 10s > 0s) {
            return (deliver);
        }
    } else {
        if (obj.ttl + obj.grace > 0s) {
            return (deliver);
        }
    }
}

sub vcl_hash {
    hash_data(req.url);
    hash_data(req.http.host);

    if (req.http.origin) {
        hash_data(req.http.origin);
    }

    return (lookup);
}

sub vcl_backend_response {

    set beresp.do_stream = true;
    set beresp.ttl = 5m;
    set beresp.grace = 30m;

    set beresp.http.x-url = bereq.url;
    set beresp.http.x-host = bereq.http.host;

    /* RGW config setting rgw_expose_bucket has to be set to True */
    set beresp.http.x-bucket = std.tolower(beresp.http.Bucket);

    /*
     * If Authorization is set we can not cache
     */
    if (bereq.http.Authorization || bereq.url ~ "AWSAccessKeyId") {
        set beresp.uncacheable = true;
        set beresp.ttl = 10s;
    }

    /*
      Cache XML responses for a short period.

      This way bucket listings on public buckets, 403s and 404s
      are cached and prevent a (D)DoS on RGW/Ceph should they be
      requested very often.
    */
    if (beresp.http.Content-Type == "application/xml") {
        set beresp.ttl = 3s;
    }

    /* Do not cache large objects */
    if (std.integer(beresp.http.Content-Length, 0) > 134217728) {
        set beresp.uncacheable = true;
        set beresp.ttl = 15m;
    }

    return (deliver);
}

sub vcl_synth {
    if (resp.status == 403) {
        set resp.status = 403;
        set resp.http.Content-Type = "application/xml; charset=utf-8";

synthetic( {"<?xml version="1.0" encoding="UTF-8"?>
<Error>
<Code>AccessDenied</Code>
</Error>
"} );

        return (deliver);
    }
}

sub vcl_backend_error {
    /*
     * Retry for a maximum of 5 times if backend response is 503
     */
    if (beresp.status == 503 && bereq.retries < 4) {
        return(retry);
    } else if (beresp.status == 503) {
        set beresp.http.Content-Type = "application/xml; charset=utf-8";
        set beresp.http.Retry-After = 30;

        synthetic( {"<?xml version="1.0" encoding="UTF-8"?>
<Error>
<Code>ServiceUnavailable</Code>
<Message>Service Unavailable</Message>
<Resource>Unknown</Resource>
<RequestId>"} + bereq.xid + {"</RequestId>
</Error>
"} );

        return (deliver);
    }
}


sub vcl_deliver {
    unset resp.http.x-url;
    unset resp.http.x-host;
    unset resp.http.x-bucket;
    unset resp.http.via;
    unset resp.http.x-varnish;

    if (resp.status >= 500 && req.restarts == 0) {
        return (restart);
    }

    if (obj.hits == 0) {
        set resp.http.X-Cache-Hit = "No";
        set resp.http.X-Cache-Hits = "0";
    } else {
        set resp.http.X-Cache-Hit = "Yes";
        set resp.http.X-Cache-Hits = obj.hits;
    }

    return (deliver);
}
