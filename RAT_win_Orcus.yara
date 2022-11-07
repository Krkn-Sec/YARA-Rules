rule RAT_win_Orcus {
   meta:
      description = "Detects Orcus RAT"
      author = "KrknSec"
      reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.orcus_rat"
      date = "2022-11-07"
      aliases = "Schnorchel"
   strings:
      $x = "Orcus.Shared.Commands.Keylogger" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and $x
      )
}