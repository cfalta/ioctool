function Initialize-Datastore
{
    $Global:iocdata = [PSCustomObject]@{
        DATASET = New-Object -TypeName "System.Collections.ArrayList"
        RAWDATA = ""
        BASEREF = [PSCustomObject]@{
            Item = ""
            #Possible types are IP, MD5, SHA1, SHA256, URL, DOMAIN
            Type = ""
        }
        ClipCount = 0
        AlwaysDefang = $false
    }
}

function Get-DataStore
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("DATASET", "RAWDATA")]
        [String]
        $Type
    )

    if($Type -eq "DATASET")
    {
        $Global:iocdata.DATASET
    }
    if($Type -eq "RAWDATA")
    {
        $Global:iocdata.RAWDATA
    }
}

function Export-DatastoreToClipboard
{

    [CmdletBinding()]
    Param (
        #Specify data type to export
        #Possible types are IP, MD5, SHA1, SHA256, URL, DOMAIN and ALL
        [Parameter(Mandatory = $true)]
        [ValidateSet("IP", "MD5", "SHA1", "SHA256", "URL", "DOMAIN", "ALL")]
        [String]
        $Type,
        #Specify output format
        #Possible types are text
        [Parameter(Mandatory = $true)]
        [ValidateSet("text")]
        [String]
        $Format
    )

    #Store the specified data into a new variable
    if($Type -eq "ALL")
    {
        $data = Get-DataStore -Type DATASET | sort Type
    }
    else
    {
        $data = Get-DataStore -Type DATASET | ? {$_.type -eq $Type}
    }

    #if $Global:iocdata.alwaysdefang is $false, undo defanging of domains and URLs
    if($Global:iocdata.alwaysdefang -eq $false)
    {
        $data = $data | % {
            if($_.type -eq "DOMAIN" -OR $_.type -eq "IP")
            {
                $_.item = $_.item -replace "\[\.\]", "."
            }
            elseif($_.type -eq "URL")
            {
                $_.item = $_.item -replace "hxxp", "http"
            }
            $_
        }
    }

    switch($Format)
    {
        text
        {
            $data | select -ExpandProperty Item | Set-Clipboard
        }
    }
}

function Show-Datastore
{
    [CmdletBinding()]
    Param (
        [Parameter()]
        [ValidateSet("Shell", "Grid", "Raw", "Stats")]
        [String]
        $Format)

    switch ($Format) {
        Shell {     
                #For future use, show as separate groups
                #$groups = (Get-Datastore -Type DATASET) | Group-Object -Property Type
                #$groups | % { $_.group | select Item,Type | ft -AutoSize } 

                #Show all IOCs in one single table
                Get-DataStore -Type DATASET | select Item,Type | sort Type | ft -AutoSize
            }
        Grid {     
                Get-DataStore -Type DATASET | select Item,Type | sort Type | Out-GridView -Title "IOCTOOL" 
            }
        Raw {     
                Get-DataStore -Type DATASET
            }
        Stats
        {
            #Use Write-Host to show the number of clips captured and the number of IOCs extracted
            Write-Host -ForegroundColor White "Clips captured: " -nonewline; Write-Host -foregroundcolor Yellow $($Global:iocdata.ClipCount)
            Write-Host -ForegroundColor White "IOCs extracted: " -nonewline; Write-Host -foregroundcolor Yellow $((Get-DataStore -Type DATASET).Count)
            #Use Write-Host to write a colored line of text that contains the number of IOCs of each type in one single line
            $groups = Get-DataStore -Type DATASET | Group-Object -Property Type
            $groups | % { Write-Host -ForegroundColor White $_.Name -nonewline; Write-Host -foregroundcolor Yellow " $($_.Count)" -nonewline; Write-Host -ForegroundColor White " | " -nonewline}
        }            
    }

}

function Read-UserInput
{
    $raw = Read-Host
    $raw
}

function Watch-Clipboard
{    
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [switch]
        $Continuous)

    if($Continuous)
    {
        $previous = ""
        $current = ""
        $raw = New-Object -TypeName "System.Collections.ArrayList"

        # Ugly hack due to timing problem in $host.UI.RawUI.KeyAvailable
        # https://github.com/PowerShell/PSReadLine/issues/959

       # start-sleep -milliseconds 1000
        #$host.ui.RawUI.FlushInputBuffer()

        while($true)
        {
           
           if([Console]::KeyAvailable) 
            {
                break 
            }

            $current = Get-Clipboard
            if($current)
            {
                if((diff $current $previous))
                {
                    $null = $raw.Add($current)
                    $Global:iocdata.RAWDATA = $raw
                    $Global:iocdata.ClipCount++
                }
                $previous = $current
            }
            sleep 1
            
        }
    }
    else {

        $raw = New-Object -TypeName "System.Collections.ArrayList"
        $current = Get-Clipboard
        if($current)
        {
            $null = $raw.Add($current)
            $Global:iocdata.RAWDATA = $raw
            $Global:iocdata.ClipCount++
        }
    }

}

function ConvertFrom-Clipboard
{
    $temp_array = New-Object -TypeName "System.Collections.ArrayList"

    foreach($rawdata in (Get-DataStore -Type RAWDATA))
    {

        # Use regex to search for IPs (normal and defanged)
        $ip = ($rawdata| sls -allmatches -Pattern "\b(?:25[0-5]|2[0-4][0-9]|[1]?[0-9][0-9]?)(?:\[\.\]|\.)(?:25[0-5]|2[0-4][0-9]|[1]?[0-9][0-9]?)(?:\[\.\]|\.)(?:25[0-5]|2[0-4][0-9]|[1]?[0-9][0-9]?)(?:\[\.\]|\.)(?:25[0-5]|2[0-4][0-9]|[1]?[0-9][0-9]?)\b").Matches.Value
        if($ip)
        {
            foreach($i in $ip)
            {
                $pso = $Global:iocdata.BASEREF.psobject.Copy()
                $pso.item = $i
                #defang IP if it is not already defanged
                if($i -notmatch "\[\.\]")
                {
                    $pso.item = $i -replace "\.", "[.]"
                }
                $pso.type = "IP"
                $null = $temp_array.add($pso)
            }

        }

        # Use regex to search for hashes
        # 32 = MD5, 40 = SHA1, 64 = SHA256

        # Use regex to search for md5 hashes
        $md5 = ($rawdata| sls -allmatches -Pattern "\b([a-fA-F\d]{32})\b").Matches.Value
        if($md5)
        {
            foreach($i in $md5)
            {
                $pso = $Global:iocdata.BASEREF.psobject.Copy()
                $pso.item = $i
                $pso.type = "MD5"
                $null = $temp_array.add($pso)
            }

        }

        # Use regex to search for sha1 hashes
        $sha1 = ($rawdata| sls -allmatches -Pattern "\b([a-fA-F\d]{40})\b").Matches.Value
        if($sha1)
        {
            foreach($i in $sha1)
            {
                $pso = $Global:iocdata.BASEREF.psobject.Copy()
                $pso.item = $i
                $pso.type = "SHA1"
                $null = $temp_array.add($pso)
            }

        }

        # Use regex to search for sha256 hashes
        $sha256 = ($rawdata| sls -allmatches -Pattern "\b([a-fA-F\d]{64})\b").Matches.Value
        if($sha256)
        {
            foreach($i in $sha256)
            {
                $pso = $Global:iocdata.BASEREF.psobject.Copy()
                $pso.item = $i
                $pso.type = "SHA256"
                $null = $temp_array.add($pso)
            }

        }

        # Use regex to search for defanged URLs
        $url_defanged = ($rawdata| sls -allmatches -Pattern "hxxp(s)?://").Matches.Value
        if($url_defanged)
        {
            foreach($i in $url_defanged)
            {
                $pso = $Global:iocdata.BASEREF.psobject.Copy()
                $pso.item = $i
                $pso.type = "URL"
                $null = $temp_array.add($pso)
            }

        }       


        #Use regex to search for regular URLs
        #source regex --> regexr.com/2s387
        $url = ($rawdata | sls -allmatches -Pattern "((https?|ftp)\:\/\/([\w-]+\.)?([\w-])+\.(\w)+\/?[\w\?\.\=\&\-\#\+\/]+)").Matches.Value
        if($url)
        {
            foreach($i in $url)
            {
                $pso = $Global:iocdata.BASEREF.psobject.Copy()
                #defang URL
                $i = $i -replace "http", "hxxp"
                $pso.item = $i
                $pso.type = "URL"
                $null = $temp_array.add($pso)
            }

        }

        # Use regex to search for defanged domains
        ## use this alternate regex to include also non-defanged domain but beware that this results in high FP rates: \b(?:[a-zA-Z0-9-]+\[\.\][a-zA-Z]{2,}\b|\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b)
        $domain_defanged = ($rawdata| sls -allmatches -Pattern "\b(?:[a-zA-Z0-9-]+\[\.\][a-zA-Z]{2,})\b").Matches.Value
        if($domain_defanged)
        {
            foreach($i in $domain_defanged)
            {
                $pso = $Global:iocdata.BASEREF.psobject.Copy()
                $pso.item = $i
                $pso.type = "DOMAIN"
                $null = $temp_array.add($pso)
            }
        }

    }
       #Dedup
       $temp_array = $temp_array | sort -Property Item -Unique
       $temp_array | % { $null = $Global:iocdata.DATASET.Add($_)}

}

function Invoke-UserDecision
{ 
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("IOC2Clipboard_Menu1", "IOC2Clipboard_Menu2")]
        [String]
        $Question
    )
    
    switch($Question)
    {
        #Ask the user which type of IOC to write back to clipboard using PowerShell's built-in menu
        IOC2Clipboard_Menu1
        {
            $choices = @()
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "&IP", "IP"
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "&MD5", "MD5"
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "&SHA1", "SHA1"
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "S&HA256", "SHA256"
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "&URL", "URL"
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "&DOMAIN", "DOMAIN"
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "&ALL", "ALL"
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel", "Cancel"

            $title = "Select IOC type"
            $message = "Select data will be written back to clipboard. If you select ALL, all IOCs will be written back to clipboard sorted by type."
            $result = $host.ui.PromptForChoice($title, $message, $choices, 0)

            switch($result)
            {
                0
                {
                    Export-DatastoreToClipboard -Type IP -Format text
                }
                1
                {
                    Export-DatastoreToClipboard -Type MD5 -Format text
                }
                2
                {
                    Export-DatastoreToClipboard -Type SHA1 -Format text
                }
                3
                {
                    Export-DatastoreToClipboard -Type SHA256 -Format text
                }
                4
                {
                    Export-DatastoreToClipboard -Type URL -Format text  
                }
                5
                {
                    Export-DatastoreToClipboard -Type DOMAIN -Format text   
                }
                6
                {
                    Export-DatastoreToClipboard -Type ALL -Format text
                }
                7
                {
                    #Cancel
                }
            }
        }
        IOC2Clipboard_Menu2
        {
            #reserverd for future use
        }
    }
}

#Main
function Invoke-IOCTool
{

    [CmdletBinding()]
    Param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Continuous)

$baseloop = $true
while($baseloop)
{
    $baseloop=$false

    Initialize-Datastore
    if($PSBoundParameters.ContainsKey('Continuous'))
    {
        Write-Host "Starting to monitor clipboard for IOC data. Press any key to stop."
        Watch-Clipboard -Continuous
    }
    else
    {
        Watch-Clipboard
    }
    ConvertFrom-Clipboard

    if((Get-DataStore -Type DATASET) -and (Get-DataStore -Type RAWDATA))
    {
    
        $global:keeplooping = $true
        while($global:keeplooping)
        {
            Clear-Host
            Write-Host "IOCTOOL" -ForegroundColor Yellow
            Write-Host "========" -ForegroundColor Yellow
            Write-Host ""
            Show-Datastore -Format Stats
            Write-Host ""

            #Ask the user what to do using PowerShell's built-in menu
            #Options: write IOCs back to clipboard, show results, show result details (gridview), restart, quit
            $choices = @()
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "&select IOCs"
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "results &brief"
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "results &gridview"
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "&quit"
            $choices += New-Object System.Management.Automation.Host.ChoiceDescription "&restart"

            $title = "What do you want to do?"
            $choice = $host.ui.PromptForChoice($title, $null, $choices, 0)

            switch($choice)
            {
                0
                {
                    Invoke-UserDecision -Question IOC2Clipboard_Menu1
                }
                1
                {
                    Show-Datastore -Format Shell
                    Write-Host -ForegroundColor Yellow "Press ENTER to continue"
                    $null=Read-UserInput
                }
                2
                {
                    Show-Datastore -Format Grid
                }
                3
                {
                    $global:keeplooping = $false
                }
                4
                {
                    $global:keeplooping = $false
                    Clear-Host
                    $baseloop = $true
                }
            }
        }
    }
    else {
        Write-Warning "No indicators found. Exiting."
    }
}
}

if(Get-alias ioctool -ErrorAction SilentlyContinue)
{
    #Using Remove-Item for PS5.1 compatibility
    Remove-Item Alias:ioctool
    New-Alias -Name "ioctool" -Value Invoke-IOCTool
}
else {
    New-Alias -Name "ioctool" -Value Invoke-IOCTool
}
