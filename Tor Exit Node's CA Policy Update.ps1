#Requires -Module @{ModuleName='Microsoft.Graph.Identity.SignIns'; RequiredVersion='2.25.0'},@{ModuleName='Microsoft.Graph.Authentication'; RequiredVersion='2.25.0'}
Connect-MgGraph -NoWelcome -Identity
Start-Job -Name "IPv4 IP Range Update" -ScriptBlock {

$url = "https://check.torproject.org/torbulkexitlist"
$response = Invoke-WebRequest -Uri $url -UseBasicParsing

$IPs=$response.RawContent -split "`n" | ForEach-Object { "$_`/32" }
$regex="^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/32$"
$CleanedIPs=$IPs -match $regex

$IPlist=$CleanedIPs | Group-Object | ForEach-Object { $_.Group[0] }
#Enter Policy Name - If it doesn't exist, it will create it.    
$PolicyName="Block Tor IPv4"
$Policy=Get-MgIdentityConditionalAccessNamedLocation -Filter "DisplayName eq '$($PolicyName)'"

$params = @{
	"@odata.type" = "#microsoft.graph.ipNamedLocation"
	DisplayName = "$PolicyName"
	IsTrusted = $false

}
$params.Add("IpRanges",@())
Foreach ($IP in $IPlist)
{
$IpRanges = @{}
$IpRanges.add("@odata.type", "#microsoft.graph.iPv4CidrRange")
$IpRanges.add("CidrAddress", $IP)
$params.IpRanges += $IpRanges
}

if ($Policy)
{
Update-MgIdentityConditionalAccessNamedLocation -NamedLocationId $Policy.Id  -BodyParameter $params
}
else 
{
New-MgIdentityConditionalAccessNamedLocation -DisplayName $PolicyName -BodyParameter $params
}
}

Start-Job -Name "IPv6 IP Range Update" -ScriptBlock {

$url = "https://www.dan.me.uk/torlist/?exit"
$response = Invoke-WebRequest -Uri $url -UseBasicParsing

$IP6s=$response.RawContent -split "`n" | ForEach-Object { "$_`/32" }
#cleanup
$regex='(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'

$CleanedIP6s=$IP6s -match $regex

$IP6list=$CleanedIP6s | Group-Object | ForEach-Object { $_.Group[0] }

$PolicyName="Block Tor IPv6"
$Policy=Get-MgIdentityConditionalAccessNamedLocation -Filter "DisplayName eq '$($PolicyName)'"
$params = @{
	"@odata.type" = "#microsoft.graph.ipNamedLocation"
	DisplayName = "Tor Exit Nodes (IPv6)"
	IsTrusted = $false
}

$params.Add("IpRanges",@())
Foreach ($IP6 in $IP6list)
{
$IpRanges = @{}
$IpRanges.add("@odata.type", "#microsoft.graph.iPv6CidrRange")
$IpRanges.add("CidrAddress", $IP6)
$params.IpRanges += $IpRanges
}
if ($Policy)
{
Update-MgIdentityConditionalAccessNamedLocation -NamedLocationId $Policy.Id  -BodyParameter $params
}
else 
{
New-MgIdentityConditionalAccessNamedLocation -DisplayName $PolicyName -BodyParameter $params
}
}
