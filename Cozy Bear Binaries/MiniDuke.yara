rule MinidukeAPT29 {
   meta:
      description = "MiniDuke binary rule from CozyBear collection"
      author = "Krkn"
      date = "2020-05-24"
   strings:
      $mz = { 4d 5a }
      $s1 = "C:\\Windows\\SysWOW64\\rundll32.exe" fullword ascii
      $s2 = "UserCache.dll" fullword ascii
      $s3 = ".?AVITempFileCreator@NtHttpModule_UrlDownloadToFile@@" fullword ascii
      $s4 = ".?AVNtHttpModule_UrlDownloadToFile@@" fullword ascii
      $s5 = ".?AVNtHttpClient_UrlDownloadToFile@@" fullword ascii
      $s6 = "}a#+ ;`>&>Dnnnnnn>/</#tn)&*($%Dnnnnnn%+7tn|w~{" fullword ascii
      $s7 = "|wv}wDnnnncn;<\"tn&::>taa999`/\"-!7+ =/ -&+`-!#a#+ ;`>&>Dnnnnnn>/</#tn&$%;$\"Dnnnnnn%+7tn|w~{" fullword ascii
      $s8 = "|wv}wDnnnncn;<\"tn&::>taa999`/*#' '=:</-'! *+(' -/=/\"-!7`-!#a#+ ;`>&>Dnnnnnn>/</#tn?)$%-\"Dnnnnnn%+7tn|w~{" fullword ascii
      $s9 = "ninvalid vector<T> subscript" fullword ascii
      $s10 = ".?AVNtHttpSystem@@" fullword ascii
      $s11 = ".?AVHttpTmpCreator@@" fullword ascii
      $s12 = ".?AVIHttpSystem@@" fullword ascii
      $s13 = ".?AVNtHostId@@" fullword ascii
      $s14 = ".?AVNtLinkInfoDll@@" fullword ascii
      $s15 = "A3-* -6A8" fullword ascii
      $s16 = ".?AVNtStartup_ExplorerShellFolders@@" fullword ascii
      $x1 = "|wv}wDnnnncn;<\"tn&::>taa999`||x+<=`+=a#+ ;`>&>Dnnnnnn>/</#tn6$ '!/Dnnnnnn%+7tn|w~{" fullword ascii
      $x2 = "|wv}wDnnnncn;<\"tn&::>taa999`(/%!\"':&`+=a#+ ;`>&>Dnnnnnn>/</#tn(/)/-Dnnnnnn%+7tn|w~{" fullword ascii
      $x3 = ".?AVIHostIdentification@@" fullword ascii
      $d1 = ": :(:0:8:<:@:H:\\:d:x:" fullword ascii
   condition:
      ( $mz at 0 ) and 
      ( filesize < 400KB and (8 of ($s*)) and (2 of ($x*)) and (1 of ($d*))
      ) or ( all of them )
}
