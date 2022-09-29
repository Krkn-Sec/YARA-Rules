rule RAT_win_9002RAT {
    meta:
        author = "KrknSec"
        description = "Detects the 9002 RAT."
        date = "2022-09-29"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.9002"
        aliases = "McRAT, Hydraq, HOMEUNIX"
    strings:
        $s1 = "www.xiazaigang.com" fullword wide
        $s2 = "j%%TEMP%%\\%s_p.ax" fullword wide /* score: '20.50'*/
        $s3 = "POST http://%ls:%d/%x HTTP/1.1" fullword ascii /* score: '15.00'*/
        $s4 = "%TEMP%\\uid.ax" fullword wide /* score: '15.00'*/
        $s5 = "_HttpAddRequestHeadersW@16" fullword ascii /* score: '12.00'*/
        $s6 = "CONNECT %ls:%d HTTP/1.1" fullword ascii /* score: '10.00'*/
        $s7 = "Untitled.exe" fullword ascii /* score: '22.00'*/
        $s8 = "c:\\windows\\system32\\clb.dll" fullword wide /* score: '37.00'*/
        $s9 = "\\walk.dat" fullword ascii /* score: '12.00'*/
        $s10 = "LoadFileFromMe" fullword ascii /* score: '4.00'*/
        $s11 = "@NT Kernel Logger" fullword wide /* score: '19.00'*/
        $s12 = "Xunlei.CPerformanceServer.Exist.Mutex" fullword wide /* score: '18.00'*/
        $s13 = "Xunlei.CPerformanceClient.Exist.Mutex" fullword wide /* score: '18.00'*/
    condition:
        (uint16(0) == 0x5a4d and filesize < 100MB and (3 of them))
}
