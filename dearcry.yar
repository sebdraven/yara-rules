rule dearcry
{
	meta:
	description = "Identifies DearCry ransomware."
	author = "@sebdraven"
	date = "2021-03"
	reference = "https://www.bleepingcomputer.com/news/security/ransomware-now-attacks-microsoft-exchange-servers-with-proxylogon-exploits/"
	tlp = "White"
	strings:
		// Basic block 00401332
		$enc = { 5? 6a 04 8d ?? ?4 2c 6a 01 5? e8 ?? ?? ?? ?? 8b ?? ?4 34 5? 5? 6a 01 5? e8 ?? ?? ?? ?? 8b ?? ?4 44 99 8b ?? 8b ?? 83 c5 0c 5? 83 d? 00 e8 ?? ?? ?? ?? 5? 6a 04 8d ?? ?4 68 6a 01 5? c7 44 ?4 70 04 00 00 00 e8 ?? ?? ?? ?? 8b ?? ?4 60 8d ?? ?4 74 5? 5? e8 ?? ?? ?? ?? 5? 6a 08 8d ?? ?4 9c 00 00 00 6a 01 5? e8 ?? ?? ?? ?? 83 c4 4c 83 c5 0c 83 d? 00 e8 ?? ?? ?? ?? 6a 01 6a 00 8b ?? 6a 00 6a 00 89 ?? ?4 38 e8 43 1b 00 00 5? 5? e8 ?? ?? ?? ?? 6a 01 8d ?? ?4 b8 00 00 00 5? 8d ?? ?4 9c 00 00 00 5? 6a 00 6a 00 5? e8 ?? ?? ?? ?? 8b ?? ?4 44 8b ?? ?4 60 5? 68 00 00 10 00 6a 01 5? e8 ?? ?? ?? ?? 8b ?? 83 c4 40 85 ??  }

	condition:
		$enc
}