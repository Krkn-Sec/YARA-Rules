rule RANSOM_win_Adhubllka {
   meta:
      author = "KrknSec"
      description = "Detects Adhubllka ransomware."
      reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.adhubllka"
      date = "2022-09-29"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "Read_Me.txt" fullword wide
      $s3 = "GdRich|" fullword ascii
      $s4 = "Attention! " fullword ascii
      $s5 = "1. Download Tor browser - https://www.torproject.org/ " fullword ascii
      $s6 = "The server with your decryptor is in a closed network TOR. You can get there by the following ways:" fullword ascii
      $s7 = "All your files, documents, photos, databases and other important files are encrypted" fullword ascii
      $s8 = "The only method of recovering files is to purchase an unique decryptor. Only we can give you this decryptor and only we can reco" ascii
      $s9 = "The only method of recovering files is to purchase an unique decryptor. Only we can give you this decryptor and only we can reco" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}