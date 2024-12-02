rule BlackSuit_ransomware {
   meta:
      description = "BlackSuit ransomware executable detection"
      author = "Aishat Motunrayo Awujola"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-10-03"

hash1= "90ae0c693f6ffd6dc5bb2d5a5ef078629c3d77f874b2d2ebd9e109d8ca049f2c"

   strings:
      $x1 = "C:\\Users\\pipi-\\source\\repos\\encryptor\\Release\\encryptor.pdb" fullword ascii
      $s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s3 = "C:\\Users\\Adm\\vcpkg\\packages\\openssl_x86-windows-static\\bin" fullword ascii
      $s4 = "C:\\Users\\Adm\\vcpkg\\buildtrees\\openssl\\x86-windows-static-rel\\providers\\implementations\\ciphers\\cipher_aes_hw_aesni.inc" ascii
      $s5 = "C:\\Users\\Adm\\vcpkg\\buildtrees\\openssl\\x86-windows-static-rel\\providers\\implementations\\ciphers\\cipher_aes_cts.inc" fullword ascii
      $s6 = "C:\\Users\\Adm\\vcpkg\\buildtrees\\openssl\\x86-windows-static-rel\\providers\\implementations\\macs\\blake2_mac_impl.c" fullword ascii
      $s7 = "get_payload_private_key" fullword ascii
      $s8 = "C:\\Users\\Adm\\vcpkg\\packages\\openssl_x86-windows-static\\lib\\engines-3" fullword ascii
      $s9 = "C:\\Users\\Adm\\vcpkg\\packages\\openssl_x86-windows-static" fullword ascii
      $s10 = "get_payload_public_key" fullword ascii
      $s11 = "C:\\Users\\Adm\\vcpkg\\buildtrees\\openssl\\x86-windows-static-rel\\crypto\\err\\err_local.h" fullword ascii
      $s12 = "C:\\Users\\Adm\\vcpkg\\buildtrees\\openssl\\x86-windows-static-rel\\providers\\implementations\\ciphers\\cipher_camellia_cts.inc" ascii
      $s13 = "C:\\Windows\\Sysnative\\bcdedit.exe" fullword wide
      $s14 = "C:\\Windows\\Sysnative\\vssadmin.exe" fullword wide
      $s15 = "error processing message" fullword ascii
      $s16 = "C:\\Users\\Adm\\vcpkg\\buildtrees\\openssl\\x86-windows-static-rel\\engines\\e_capi_err.c" fullword ascii
      $s17 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s18 = "get_dh_dsa_payload_p" fullword ascii
      $s19 = "loader incomplete" fullword ascii
      $s20 = "get_payload_group_name" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and 4 of them
}
