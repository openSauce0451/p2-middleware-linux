$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $a = $request.args
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    function Checked-Index($index) {
        $n = [uint32]$index
        if ($n -eq 0) { throw 'Invalid interface' }
        return $n
    }
    function Checked-Rule($name) {
        if ([string]$name -cnotmatch '^p2-middleware-[0-9a-fA-F]{16}(-udp)?$') { throw 'Invalid rule name' }
        return [string]$name
    }
    function Assert-Rule($rule,$alias,$expected,$r,$protocol,$port) {
        $portFilter=$rule | Get-NetFirewallPortFilter
        $address=$rule | Get-NetFirewallAddressFilter
        $app=$rule | Get-NetFirewallApplicationFilter
        $interface=$rule | Get-NetFirewallInterfaceFilter
        $locals=@($address.LocalAddress | Sort-Object)
        $remotes=@($address.RemoteAddress);$aliases=@($interface.InterfaceAlias)
        if($rule.Group -ne 'P2MiddlewareOwned' -or $rule.Direction -ne 'Inbound' -or $rule.Action -ne 'Allow' -or $rule.Enabled -ne 'True' -or $rule.Profile -ne 'Any' -or $rule.EdgeTraversalPolicy -ne 'Block' -or
            $aliases.Count -ne 1 -or [string]$aliases[0] -ne $alias -or
            $portFilter.Protocol -ne $protocol -or [string]$portFilter.LocalPort -ne [string]$port -or [string]$portFilter.RemotePort -ne 'Any' -or
            [string]$app.Program -ne [string]$r.program -or $remotes.Count -ne 1 -or [string]$remotes[0] -ne [string]$r.peer -or
            $locals.Count -ne $expected.Count -or @(Compare-Object $locals $expected).Count -ne 0){throw 'Native rule ownership conflict'}
    }
    $result = switch ($request.operation) {
        'native_addresses_free' {
            $found=@(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -in @($a.addresses) })
            if($found.Count -ne 0){throw 'Native address already present'}
            $true;break
        }
        {$_ -in 'native_rule_add','native_rule_remove'} {
            if(-not $admin){throw 'Administrator required'}
            $r=$a.record
            $name=Checked-Rule $r.name
            $udpName=Checked-Rule "$name-udp"
            $alias=(Get-NetAdapter -InterfaceIndex (Checked-Index $r.index)).Name
            $expected=@($a.addresses | ForEach-Object {[string]$_} | Sort-Object)
            if($expected.Count -ne 26){throw 'Native address bounds'}
            $plan=@(@{name=$name;protocol='TCP'},@{name=$udpName;protocol='UDP'})
            foreach($entry in $plan){
                $items=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Name -eq $entry.name)
                if($request.operation -eq 'native_rule_add'){
                    if($items.Count -ne 0){throw 'Native rule exists'}
                    New-NetFirewallRule -PolicyStore PersistentStore -Name $entry.name -DisplayName "P2 middleware temporary gateway ($($entry.protocol))" -Group 'P2MiddlewareOwned' -Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol $entry.protocol -LocalPort 27017 -LocalAddress $expected -RemoteAddress ([string]$r.peer) -Program ([string]$r.program) -InterfaceAlias $alias -EdgeTraversalPolicy Block | Out-Null
                    $items=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Name -eq $entry.name)
                }
                if($items.Count -ne 0){
                    if($items.Count -ne 1){throw 'Native rule ambiguity'}
                    Assert-Rule $items[0] $alias $expected $r $entry.protocol 27017
                    if($request.operation -eq 'native_rule_remove'){
                        Remove-NetFirewallRule -PolicyStore PersistentStore -Name $entry.name
                    }
                } elseif($request.operation -eq 'native_rule_add'){throw 'Native rule missing'}
                if($request.operation -eq 'native_rule_remove' -and @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Name -eq $entry.name).Count -ne 0){throw 'Native rule remains'}
            }
            $true;break
        }
        default { throw 'Unknown native operation' }
    }
    ConvertTo-Json -InputObject $result -Compress -Depth 8
} catch { exit 1 }
