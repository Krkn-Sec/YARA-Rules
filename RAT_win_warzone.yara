rule RAT_win_warzone {
   meta:
      description = "Detects AveMaria/Warzone RAT binaries."
      author = "KrknSec"
      reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ave_maria"
      date = "2022-11-11"
   strings:
      $s1 = "find.exe" fullword ascii
      $s2 = "SMTP Password" fullword wide 
      $s3 = "\\sqlmap.dll" fullword wide 
      $s5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" fullword ascii 
      $s6 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A667" wide 
      $s7 = "/n:%temp%\\ellocnak.xml" fullword wide 
      $s8 = "POP3 Password" fullword wide
      $s9 = "IMAP Password" fullword wide 
      $s10 = "\\Google\\Chrome\\User Data\\Default\\Login Data" fullword wide 
      $s11 = "\\logins.json" fullword wide 
      $s12 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide 
      $s13 = "HTTP Password" fullword wide 
      $s15 = "encryptedUsername" fullword ascii 
      $s16 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676" fullword wide 
      $s17 = "blicKeyToken=\"31bf3856ad364e35\"/>" fullword ascii
      $s18 = "ellocnak.xml" fullword wide 
      $s19 = "-w %ws -d C -f %s" fullword ascii
      $s20 = "POP3 User" fullword wide

      $op0 = { 0f 11 45 f0 e8 99 fc ff ff ff 75 08 8b c8 e8 02 }
      $op1 = { 0f 11 45 f0 e8 d2 f6 ff ff ff 75 08 8b c8 e8 3b }
      $op2 = { e8 50 ff ff ff a3 74 2b 55 00 c3 a1 c4 30 55 00 }
   condition:
      ( 
         ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and 
         filesize < 9000KB and ( 8 of them ) and all of ($op*)
      ) or 
      ( all of them )
}