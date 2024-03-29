rule xmrig {
  meta:
    description = "xmrig detection based on versions 2.8, 2.9, 3.0, 3.1"
    author = "KrknSec"
    date = "2019-08-31"
  strings:
    $mz = { 4d 5a }
    $x1 = "xmrig.exe" fullword wide
    $x2 = "donate.ssl.xmrig.com" fullword ascii
    $x3 = "www.xmrig.com" fullword wide
    $s1 = "[%s] login error code: %d" fullword ascii
    $s2 = "ossl_statem_server_post_process_message" fullword ascii
    $s3 = "tls_early_post_process_client_hello" fullword ascii
    $s4 = "ossl_statem_client_post_process_message" fullword ascii
    $s5 = "tls_post_process_client_hello" fullword ascii
    $s6 = "tls_post_process_client_key_exchange" fullword ascii
    $s7 = "tls_process_encrypted_extensions" fullword ascii
    $s8 = "* COMMANDS 'h' hashrate, 'p' pause, 'r' resume" fullword ascii
    $s9 = "donate.v2.xmrig.com" fullword ascii
    $s10 = "ossl_store_get0_loader_int" fullword ascii
    $s11 = "tls_process_new_session_ticket" fullword ascii
    $s12 = "loader incomplete" fullword ascii
    $s13 = "[%s:%u] getaddrinfo error: \"%s\"" fullword ascii
    $s14 = "log conf missing description" fullword ascii
    $s15 = "temporary failure" fullword ascii
    $s16 = "dtls1_process_buffered_records" fullword ascii
    $s17 = "dtls_process_hello_verify" fullword ascii
    $z1 = "Permission denied" fullword ascii
    $z2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide
    $z3 = "system" fullword ascii

  condition:
    $mz at 0 and
    all of ($x*) and 8 of ($s*) and 1 of ($z*) and
    filesize < 19000KB
}
