rule RAT_win_9002RAT {
    meta:
        author = "KrknSec"
        description = "Detects the 9002 RAT."
        date = "2022-09-29"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.9002"
        aliases = "McRAT, Hydraq, HOMEUNIX"
    strings:
        $s1 = "www.xiazaigang.com" fullword wide
        $s2 = "j%%TEMP%%\\%s_p.ax" fullword wide
        $s3 = "POST http://%ls:%d/%x HTTP/1.1" fullword ascii
        $s4 = "%TEMP%\\uid.ax" fullword wide
        $s5 = "_HttpAddRequestHeadersW@16" fullword ascii
        $s6 = "CONNECT %ls:%d HTTP/1.1" fullword ascii
        $s7 = "Untitled.exe" fullword ascii
        $s8 = "c:\\windows\\system32\\clb.dll" fullword wide
        $s9 = "\\walk.dat" fullword ascii
        $s10 = "LoadFileFromMe" fullword ascii
        $s11 = "@NT Kernel Logger" fullword wide
        $s12 = "Xunlei.CPerformanceServer.Exist.Mutex" fullword wide
        $s13 = "Xunlei.CPerformanceClient.Exist.Mutex" fullword wide
    condition:
        (uint16(0) == 0x5a4d and filesize < 100MB and (3 of them))
}
