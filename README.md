what is rat snake?

-execute commands against android devices using the android debug bridge protocol<br>
-support for proxychains, traffic can be routed through tor network<br>
-support for threading, can target many devices at once<br>
-support for saving command output to file<br>
-support for shell and exec command execution<br>
-supports targeting ipv4 networks or reading targets from a list<br>
-ipv6 not supported<br>
-adb authorization not supported<br>

-how to get device name, model, and features 
cat output/results.json | jq -s '.[] | if(has("device_header")) then . else empty end | {ip,device:.device_header|@base64d|split(";")}|{ip,name:.device[0],model:.device[1],device:.device[2],features:.device[3]}'
