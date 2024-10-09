# Set to true if you want to acquire a fresh token
$getFreshToken = $false

# Set to true if you want to generate the list of apps to scan
$generateListToScan = $false

# Function to acquire a fresh token
function Get-FreshToken {
    Install-Module -Name MSAL.PS -Scope CurrentUser -Force
    $clientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e' # Microsoft Graph Command Line Tools
    $scopes = "Directory.Read.All", "Policy.Read.All", "Policy.ReadWrite.ApplicationConfiguration", "Subscription.Read.All", "User.Read", "User.Read.All", "Application.Read.All"
    $tokenResponse = Get-MsalToken -ClientId $clientId -Scopes $scopes -Interactive -UseEmbeddedWebView
    return $tokenResponse.AccessToken
}

# Acquire token based on the flag
if ($getFreshToken -eq $true) {
    $accessToken = Get-FreshToken
}
else {
    $accessToken = "eyJ0eXAiOiJKV1Q....."
}

# Delete the apps.csv file if it exists
if (Test-Path "apps.csv") {
    Remove-Item "apps.csv"
}

# Set the headers
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# Function to fetch all service principals
$url = "https://graph.microsoft.com/beta/servicePrincipals"
$nextPageUrl = $url
function Get-ServicePrincipals {
    # Delete the AppsToList.csv file if it exists
    if (Test-Path "AppsToList.csv") {
        Remove-Item "AppsToList.csv"
    }
    while ($nextPageUrl) {
        try {
            $response = Invoke-RestMethod -Uri $nextPageUrl -Headers $headers -Method Get
            foreach ($value in $response.value) {
                $allResults = [PSCustomObject]@{
                    id            = $value.id
                    appId         = $value.appId
                    displayName   = $value.displayName
                    publisherName = $value.publisherName
                }
                $allResults | Export-Csv -Path "AppsToList.csv" -NoTypeInformation -Append
            }
            $nextPageUrl = $response.'@odata.nextLink'
        }
        catch {
            Write-Warning "Failed to fetch service principals for URL: $nextPageUrl"
            Write-Warning $_.Exception.Message
            Write-Warning $_.Exception.Response.Content
            $nextPageUrl = $null
        }
    }
}

# Generate the list of apps to scan if required
if ($generateListToScan -eq $true) {
    Get-ServicePrincipals
}

# Load the CSV file
$csvData = Import-Csv -Path "AppsToList.csv"

# Display the contents of the CSV file
$csvData | Format-Table -AutoSize

# Initialize an array to hold the custom objects
$Global:appsTesult = @()

# Function to fetch claims policy
function Get-ClaimsPolicy {
    param (
        [string]$SPNId,
        [string]$appId,
        [string]$appDisplayName
    )
    $claimsPolicyUrl = "https://graph.microsoft.com/beta/servicePrincipals/$SPNId/claimsPolicy"
    Write-Output "Searching for claims policy at $claimsPolicyUrl"
    try {
        $responseClaims = Invoke-RestMethod -Uri $claimsPolicyUrl -Headers $headers -Method Get
        foreach ($claim in $responseClaims) {
            foreach ($config in $claim.claims) {
                foreach ($value in $config.configurations) {
                    Write-Output "Object ID $SPNId, AppName $appDisplayName, nameIdFormat $($config.nameIdFormat), name $($config.name), ID: $($value.attribute.id), Source: $($value.attribute.source)"
                    $appsTesult = [PSCustomObject]@{
                        ObjectID     = $SPNId
                        AppID        = $appId
                        AppName      = $appDisplayName
                        NameIdFormat = $config.nameIdFormat
                        Name         = $config.name
                        AttributeID  = $value.attribute.id
                        Source       = "SAML"
                        InnerSource  = $value.attribute.source
                    }
                    $appsTesult | Export-Csv -Path "apps.csv" -NoTypeInformation -Append
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to fetch claims policy for URL: $claimsPolicyUrl"
        Write-Warning $_.Exception.Message
        Write-Warning $_.Exception.Response.Content
    }
}

# Function to fetch OIDC policy
function Get-OIDCPolicy {
    param (
        [string]$SPNId,
        [string]$appId,
        [string]$appDisplayName
    )
    $appIDInfo = "https://graph.microsoft.com/v1.0/applications(appId='$appId')"
    try {
        $responseAppID = Invoke-RestMethod -Uri $appIDInfo -Headers $headers -Method Get
        foreach ($claim in $responseAppID.optionalClaims) {
            foreach ($tokeninfo in $claim.accessToken) {
                foreach ($value in $tokeninfo) {
                    Write-Output "Object ID $($value.name)"
                    $appsTesult = [PSCustomObject]@{
                        ObjectID     = $SPNId
                        AppID        = $appId
                        AppName      = $appDisplayName
                        NameIdFormat = ""
                        Name         = $value.name
                        AttributeID  = $value.name
                        Source       = "OIDC"
                        InnerSource  = $value.source
                    }
                    $appsTesult | Export-Csv -Path "apps.csv" -NoTypeInformation -Append
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to fetch OIDC policy for URL: $appIDInfo"
        Write-Warning $_.Exception.Message
        Write-Warning $_.Exception.Response.Content
    }
}

# Function to fetch SCIM policy
function Get-SCIMPolicy {
    param (
        [string]$SPNId,
        [string]$appId,
        [string]$appDisplayName
    )
    $scimJobsInfo = "https://graph.microsoft.com/v1.0/servicePrincipals/$SPNId/synchronization/jobs/"
    try {
        $responseSCIMJobsInfo = Invoke-RestMethod -Uri $scimJobsInfo -Headers $headers -Method Get
        $jobSchemaID = ($responseSCIMJobsInfo.value[0]).id
        $scimJobSchemaInfo = "https://graph.microsoft.com/v1.0/servicePrincipals/$SPNId/synchronization/jobs/$jobSchemaID/schema/"
        $responseSCIMJobSchemaInfo = Invoke-RestMethod -Uri $scimJobSchemaInfo -Headers $headers -Method Get
        foreach ($objMapping in ($responseSCIMJobSchemaInfo.synchronizationRules[0]).objectMappings) {
            foreach ($mapping in $objMapping.attributeMappings) {
                foreach ($mappingValue in $mapping.source) {
                    Write-Output "SCIM Source ID $($mappingValue.name)"
                    $appsTesult = [PSCustomObject]@{
                        ObjectID     = $SPNId
                        AppID        = $appId
                        AppName      = $appDisplayName
                        NameIdFormat = ""
                        Name         = $mapping.targetAttributeName
                        AttributeID  = $mapping.source[0].expression
                        Source       = "SCIM"
                        InnerSource  = $objMapping.sourceObjectName                       
                    }
                    $appsTesult | Export-Csv -Path "apps.csv" -NoTypeInformation -Append
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to fetch SCIM policy for URL: $scimJobsInfo"
        Write-Warning $_.Exception.Message
        Write-Warning $_.Exception.Response.Content
    }
}

# Process each app in the CSV data
foreach ($app in $csvData) {
    if (-not [string]::IsNullOrEmpty($app.id)) {
        $SPNId = $app.id
        $appId = $app.appId
        $appDisplayName = $app.displayName

        Write-Output $app.displayName, $app.id

        Get-ClaimsPolicy -SPNId $SPNId -appId $appId -appDisplayName $appDisplayName
        Get-OIDCPolicy -SPNId $SPNId -appId $appId -appDisplayName $appDisplayName
        Get-SCIMPolicy -SPNId $SPNId -appId $appId -appDisplayName $appDisplayName

    }
    else {
        Write-Output "Skipping entry with empty ID"
    }
}