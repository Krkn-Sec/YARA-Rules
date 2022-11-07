rule RAT_win_njrat {
   meta:
      description = "Detects njRAT binaries."
      author = "KrknSec"
      reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat"
      date = "2022-11-07"
      aliases = "Bladabindi"
   strings:
      $s1 = "ShiftKeyDown" fullword wide
      $s2 = "OSFullName" fullword wide
      $s3 = "Download ERROR" fullword wide
      $s4 = "Njrat 0.7 Golden By Hassan Amiri" fullword wide
      $s5 = "[nj]PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXP" ascii
      $s6 = "netsh firewall add allowedprogram \"" fullword wide
      $s7 = "cmd.exe /k ping 0 & del \"" fullword wide

      $op0 = { e7 fe ff ff f0 fe ff ff 04 ff ff ff 52 ff ff ff }
      $op1 = { b7 ff ff ff de 22 75 17 00 00 01 14 fe 03 11 09 }
      $op2 = { 1e 02 28 01 00 00 0a 2a 1e 02 28 04 00 00 0a 2a }
      $op3 = { 61 01 00 34 53 79 73 74 65 6d 2e 57 65 62 2e 53 }
      $op4 = { 3e 29 ff ff ff 17 28 69 00 00 0a 38 1c ff ff ff }
      $op5 = { 83 00 80 0e 3d 04 02 00 34 21 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 4 of them ) and ( ($op0 and $op1 and $op2) or ($op3 and $op4 and $op5) )
      )
}