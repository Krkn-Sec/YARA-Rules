rule _SeaDaddyImplant {
   meta:
      description = "SeaDaddyImplant binary rule from the CozyBear collection"
      author = "Krkn"
      date = "2020-05-24"
   strings:
      $mz = {4d 5a}
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchitecture=\"x86\" publicKeyToke" ascii
      $s2 = "PYTHON27.DLL" fullword wide
      $s3 = "subprocess.pyo" fullword ascii
      $s4 = "G727.DLL" fullword ascii
      $s5 = "getpass.pyo}V" fullword ascii
      $s6 = "subprocess.pyoPK" fullword ascii
      $s7 = "tempfile.pyo" fullword ascii
      $s8 = "unicodedata.pyd" fullword ascii
      $s9 = "ftplib.pyo" fullword ascii
      $s10 = "getpass.pyoPK" fullword ascii
      $s11 = "gettext.pyo" fullword ascii
      $s12 = "getopt.pyo}WAs" fullword ascii
      $s13 = "_MozillaCookieJar.pyo" fullword ascii
      $s14 = "tempfile.pyoPK" fullword ascii
      $s15 = "MJCJKJGJg" fullword ascii /* base64 encoded string '$"J$b`' */
      $s16 = "cookielib.pyo" fullword ascii
      $s17 = "UserDict.pyo" fullword ascii
      $s18 = "httplib.pyo" fullword ascii
      $s19 = "keyword.pyo" fullword ascii
      $s20 = "tokenize.pyo" fullword ascii
      $x1 = "Frv~Y(" fullword ascii
      $x2 = "F+;u:" fullword ascii
      $x3 = "F W@" fullword ascii
      $x4 = "FOpS]" fullword ascii
   condition:
      ( $mz at 0) and
      ( filesize < 9000KB and ( 16 of ($s*)) and ( 2 of ($x*))
      ) or ( all of them )
}

