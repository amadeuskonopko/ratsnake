what is rat snake?

-execute commands against android devices using the android debug bridge protocol<br>
-support for proxychains, traffic can be routed through tor network<br>
-support for threading, can target many devices at once<br>
-support for saving command output to file<br>
-support for shell and exec command execution<br>
-supports targeting ipv4 networks or reading targets from a list<br>
-ipv6 not supported<br>
-adb authorization not supported<br>

-how to get device name, model, and features<br> 
cat output/results.json | jq -s '.[] | if(has("device_header")) then . else empty end | {ip,device:.device_header|@base64d|split(";")}|{ip,name:.device[0],model:.device[1],device:.device[2],features:.device[3]}'<br>
<br>
-how to get results from commands<br>
cat output/results.json | jq -cs '.[] | if(has("cmds")) then . else empty end | {ip,command:.cmds[],device:.device_header|@base64d|split(";")}|{ip,cmd:.command.cmd,output:.command.data|@base64d,name:.device[0],model:.device[1],device:.device[2],features:.device[3]}' | jq -s '.'<br>
<br>
-find devices that are secured<br>
cat output/results.json | jq 'if(.secured) then . else empty end'<br>
<br>
-look at unique list of packages
cat output/online-packages.json | jq -c '{ip,cmd:.cmds[]} | {ip,cmd:.cmd.cmd,output:.cmd.data|@base64d}| if(.output|test("^Error")) then empty else . end | {ip,package:.output|split("package:")[]} | if(.package|test("^/")) then .package=(.package|split("=")[1]) else . end | {ip,package:.package|rtrimstr("\n")|rtrimstr("\r")}|.package' | sort | uniq -c | sort -n
