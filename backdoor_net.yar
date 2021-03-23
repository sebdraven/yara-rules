rule backdoor_net{
	meta:
		description= "Backdoor targets Mongolia"
		author= "@sebdraven"
		date = "2020-03-23"
		reference = "https://sebdraven.medium.com/a-net-rat-target-mongolia-9c1439c39bc2"
		tlp = "white"
	strings:
		$s1="RunHide"
		$s2="Token"
		$s3="BasicKey"
		$s4="SessionKey"
		$s5="AdminKeyMD5"
		$s6="Aes256"
		$s7="Order_Catcher"
		$s8="Get_ComputerInfo"
		$s9="TransData"
	condition:
		all of them
}