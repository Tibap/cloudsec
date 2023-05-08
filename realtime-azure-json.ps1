<#
    .DESCRIPTION
        A runbook to retrieve Falcon assets information

    .NOTES
        PERMISSIONS: 1/ Automation Account managed ID must have access to the Key Vault to retrieve API secrets
        2/ Automation Account managed ID must have access to Storage Account to read and write the blob.
        AUTHOR: Dimitri
#>

function compareObjects ($devices, $known_devices) {
    # Convert devices to hashtable
    $map = @{}
    $map2 = @{}
    foreach($line in $devices) {
        $map.Add($line.hostname,$line.external_ip)
        $map2.Add($line.hostname,$line.country)
    }

    $result = [system.collections.generic.list[pscustomobject]]::new()

    $map.Keys.ForEach({
        if($_ -notin $known_devices.hostname) {
            $result.Add(
                [pscustomobject]@{
                    hostname = $_
                    old_ip = $map[$_]
                    external_ip = $null
                    country = $map2[$_]
                    status = 'REMOVED'
            })
        }
    })

    foreach($line in $known_devices) {
        $out = [ordered]@{
            hostname = $line.hostname
            external_ip = $line.external_ip
            country = $line.country
        }
        if(-not $map.ContainsKey($line.hostname)) {
            $out.old_ip = $null
            $out.status = 'ADDED'
            $result.Add([pscustomobject]$out)
            continue
        }

        $out.old_ip = $map[$line.hostname]

        switch($line.external_ip) {
            {$_ -eq $map[$line.hostname]}
            {
                $out.status = 'STILL'
                continue
            }
            Default
            {
                $out.status = 'IP_CHANGED'
            }
        }

        $result.Add([pscustomobject]$out)
    }

    return $result
}


$splat = @{
    Identity = $true
    AccountId = "a206c6d9-dce3-4ae8-99e8-13197ad62742" #The obj ID of the Automation Account
}

try
{
    Connect-AzAccount @splat | Out-null
    $csKey = Get-AzKeyVaultSecret -VaultName 'crowdstrikeapiinfo' -Name 'client-secret' -AsPlainText
    $csId = Get-AzKeyVaultSecret -VaultName 'crowdstrikeapiinfo' -Name 'client-id' -AsPlainText

    # Get list from Falcon API
    Request-FalconToken -ClientId $csId -ClientSecret $csKey -Hostname 'https://api.us-2.crowdstrike.com'
    $devices = Get-FalconAsset -detailed -Filter "entity_type:'managed'+country:!'Canada'+last_seen_timestamp:>'now-1d'" | select hostname, external_ip, country
    
    # Get previous list from json file in Storage Account
    $host_list_file = 'hosts-list.json'
    $ctx = New-AzStorageContext -StorageAccountName 'test' 
    Get-AzStorageBlobContent -Blob $host_list_file -Container 'hosts-outside-canada' -Destination $host_list_file -Context $ctx -Force
    $known_devices = (Get-Content -Path $host_list_file | ConvertFrom-Json) | Where-Object status -ne 'REMOVED'

	$res = compareObjects $known_devices $devices 
    # Get ADDED devices
    $added_devices = $res | Where-Object status -eq 'ADDED'
    # Get REMOVED devices
    $removed_devices = $res | Where-Object status -eq 'REMOVED'
    # Get IP_CHANGED devices
    $changed_devices = $res | Where-Object status -eq 'IP_CHANGED'

    if ($added_devices -or $removed_devices -or $changed_devices) {
        Write-Output "Change detected"
        # Get devices outside of the country
        $outofcountry = $res | Where-Object {($_.status -eq 'ADDED') -or ($_.status -eq 'STILL') -or ($_.status -eq 'IP_CHANGED')}

        Write-Output "Added devices:" $added_devices
        Write-Output "Removed devices:" $removed_devices
        Write-Output "Devices out of the country:" $outofcountry
        
		#Does not upload a UTF-8 file for some reason...
        #$outofcountry | Select-Object -Property hostname, external_ip, country, status | ConvertTo-Json | Out-File $host_list_file

        $JSONConvert = $res | Select-Object -Property hostname, external_ip, country, status | ConvertTo-Json
        $JSONEncode = [System.Text.UTF8Encoding]::new($false) 
        [System.IO.File]::WriteAllLines( (Join-path (Get-Location).path $host_list_file), $JSONConvert, $JSONEncode)
        
        # Save file in blob container
        Set-AzStorageBlobContent -Container 'hosts-outside-canada' -Blob $host_list_file -File $host_list_file -Context $ctx -Properties @{"ContentEncoding" = "UTF-8"} -Force
    }
    else {
        Write-Output "No change detected"
    }
}
catch {
    Write-Error -Message $_.Exception
    throw $_.Exception
}