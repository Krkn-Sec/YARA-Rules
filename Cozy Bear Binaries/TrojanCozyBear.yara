rule _TrojanCozyBear {
   meta:
      description = "TrojanCozyBear binary rule from the CozyBear Collection"
      author = "Krkn"
      date = "2020-05-24"
   strings:
      $mz = { 4d 5a }
      $s1 = "atiode.exe" fullword wide
      $s2 = "Copyright (c) 2007 - 2013, Advanced Micro Devices, Inc." fullword wide
      $s3 = "z1pndg.mua`+fxnm " fullword ascii
      $s4 = "Advanced Micro Devices, Inc.0" fullword ascii
      $s5 = "Advanced Micro Devices, Inc" fullword wide
      $d1 = "vwtk4Sf" fullword ascii
      $d2 = "~RKIR^EsS^U" fullword ascii
      $d3 = "MzPL?&" fullword ascii
      $d4 = "snwW/)FCh" fullword ascii
      $d5 = "uTVWhHx@" fullword ascii
      $x1 = "PADDINGXX"
      
   condition:
      ( $mz at 0 ) and
      ( filesize < 1000KB and ( 3 of ($s*)) and ( 2 of ($d*)) and (1 of ($x*))
      ) or ( all of them )
}
