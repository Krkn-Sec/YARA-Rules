rule xmrig_config {
  meta:
    description = "config file detection - from xmrig versions 2.8, 2.9, 3.0, 3.1"
    author = "KrknSec"
    date = "2019-08-31"
  strings:
    $mz = { 7b 0a }
    $x1 = "donate-level" fullword ascii
    $x2 = "nicehash" fullword ascii
    $x3 = "access-token" fullword ascii
    $s1 = "user-agent" ascii
    $s2 = "url" fullword ascii
    $s3 = "log-file" fullword ascii
    $s4 = "port" fullword ascii
    $s5 = "pass" fullword ascii
    $s6 = "keepalive" fullword ascii
    $s7 = "retries" fullword ascii
    $s8 = "colors" fullword ascii
    $s9 = "huge-pages" fullword ascii
    $s10 = "background" fullword ascii
    $s11 = "autosave" fullword ascii
    $s12 = "retry-pause" fullword ascii
    $s13 = "pools" fullword ascii
    $s14 = "restricted" fullword ascii
    $s15 = "print-time" fullword ascii
    $s16 = "asm" fullword ascii

  condition:
    ( $mz at 0 and filesize < 3KB and ( 2 of ($x*)) and ( 8 of ($s*) )
    ) or ( all of them and filesize < 3KB )
}
