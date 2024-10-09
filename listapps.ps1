
$getFreshToken = $false

if ($getFreshToken -eq $true) {
    # # Replace with your Azure AD application's client ID, or use a well-known client ID for public clients
    Install-Module -Name MSAL.PS -Scope CurrentUser
    $clientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e' # Microsoft Graph Command Line Tools

    # Define the scopes you need
    $scopes = "Directory.Read.All", "Policy.Read.All", "Policy.ReadWrite.ApplicationConfiguration", "Subscription.Read.All", "User.Read", "User.Read.All", "Application.Read.All"

    # Acquire the token interactively
    $tokenResponse = Get-MsalToken -ClientId $clientId -Scopes $scopes -Interactive -UseEmbeddedWebView

    # Extract the access token
    $accessToken = $tokenResponse.AccessToken
}
else {
    $accessToken = "eyJ0eXAiOiJK..."
}

#delete the apps.csv file if it exists
if (Test-Path "apps.csv") {
    Remove-Item "apps.csv"
}

# Set the headers
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# if you want to generate the list of apps to scan, set this to true
$generateListToScan = $false
$url = "https://graph.microsoft.com/beta/servicePrincipals"
$nextPageUrl = $url
if ($generateListToScan -eq $true) {

    # Initialize variables for pagination
    $allResults = @()

    # Loop to fetch all pages
    while ($nextPageUrl) {
        try {
            # Fetch the current page
            $response = Invoke-RestMethod -Uri $nextPageUrl -Headers $headers -Method Get
    
            foreach ($value in $response.value) {
                $allResults += [PSCustomObject]@{
                    id            = $value.id
                    appId         = $value.appId
                    displayName   = $value.displayName
                    publisherName = $value.publisherName
                }
            }

            # Check if there is a next page
            if ($response.'@odata.nextLink') {
                $nextPageUrl = $response.'@odata.nextLink'
            }
            else {
                $nextPageUrl = $null
            }

        }
        catch {
            Write-Warning "Failed to fetch claims policy for URL: $claimsPolicyUrl"
            Write-Warning $_.Exception.Message
            Write-Warning $_.Exception.Response.Content
            $nextPageUrl = $null
        }
    }

    # Export the array to a CSV file
    $allResults  | Export-Csv -Path "AppsToList.csv" -NoTypeInformation
}

# Load the CSV file
$csvData = Import-Csv -Path "AppsToList.csv"

# Display the contents of the CSV file
$csvData | Format-Table -AutoSize

# Initialize an array to hold the custom objects
$appsTesult = @()

foreach ($app in $csvData) {

    # $allResults | ForEach-Object {
    if (-not [string]::IsNullOrEmpty($app.id)) {
        $SPNId = $app.id
        $appId = $app.appId
        $appDisplayName = $app.displayName

        Write-Output $app.displayName, $app.id

        # Correct URL for fetching claims policy
        $claimsPolicyUrl = "https://graph.microsoft.com/beta/servicePrincipals/$($app.id)/claimsPolicy"
        Write-Output "Searching for claims policy at $claimsPolicyUrl"

        # Initialize an array to hold the custom objects
        $appsTesult = @()

        try {
            # Make the request for claims policy
            $responseClaims = Invoke-RestMethod -Uri $claimsPolicyUrl -Headers $headers -Method Get
            foreach ($claim in $responseClaims) {
                foreach ($config in $claim.claims) {
                    foreach ($value in $config.configurations) {
                        Write-Output "Object ID $SPNId, AppName $appDisplayName,  nameIdFormat $($config.nameIdFormat), name $($config.name) , ID: $($value.attribute.id), Source: $($value.attribute.source)"
                        $appsTesult += [PSCustomObject]@{
                            ObjectID     = $SPNId
                            AppID        = $appId
                            AppName      = $appDisplayName
                            NameIdFormat = $($config.nameIdFormat)
                            Name         = $($config.name)
                            AttributeID  = $($value.attribute.id)
                            Source       = "SAML"
                            InnerSource  = $($value.attribute.source)
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "appDisplayName: $appDisplayName, appID: $appId, SPNId: $SPNId"
            Write-Warning "Failed to fetch claims policy for URL: $claimsPolicyUrl"
            Write-Warning $_.Exception.Message
            Write-Warning $_.Exception.Response.Content
        }

        # Do the same for OIDC
        $appIDInfo = "https://graph.microsoft.com/v1.0/applications(appId='$appId')"

        try {
            # Make the request for claims policy
            $responseAppID = Invoke-RestMethod -Uri $appIDInfo -Headers $headers -Method Get
            foreach ($claim in $responseAppID.optionalClaims) {
                foreach ($tokeninfo in $claim.accessToken) {
                    foreach ($value in $tokeninfo) {
                        Write-Output "Object ID $($value.name)"

                        $appsTesult += [PSCustomObject]@{
                            ObjectID     = $SPNId
                            AppID        = $appId
                            AppName      = $appDisplayName
                            NameIdFormat = ""
                            Name         = $($value.name)
                            AttributeID  = $($value.name)
                            Source       = "OIDC"
                            InnerSource  = $($value.source)
                        }
                    }
                }
                foreach ($tokeninfo in $claim.idToken) {
                    foreach ($value in $tokeninfo) {
                        Write-Output "Object ID $($value.name)"
                    }
                }
                foreach ($tokeninfo in $claim.saml2Token) {
                    foreach ($value in $tokeninfo) {
                        Write-Output "Object ID $($value.name)"
                    }
                }                                
            }
        }
        catch {
            Write-Warning "appDisplayName: $appDisplayName, appID: $appId, SPNId: $SPNId"
            Write-Warning "Failed to fetch claims OIDC policy for URL: $appIDInfo"
            Write-Warning $_.Exception.Message
            Write-Warning $_.Exception.Response.Content
        }


        try {
            # Do the same for SCIM
            $scimJobsInfo = "https://graph.microsoft.com/v1.0/servicePrincipals/$SPNId/synchronization/jobs/"
            
            # Make the request for claims policy
            $responseSCIMJobsInfo = Invoke-RestMethod -Uri $scimJobsInfo -Headers $headers -Method Get
            
            $jobSchemaID = ($responseSCIMJobsInfo.value[0]).id
            
            $scimJobSchemaInfo = "https://graph.microsoft.com/v1.0/servicePrincipals/$SPNId/synchronization/jobs/$jobSchemaID/schema/"

            $responseSCIMJobSchemaInfo = Invoke-RestMethod -Uri $scimJobSchemaInfo -Headers $headers -Method Get
            
            foreach ($objMapping in ($responseSCIMJobSchemaInfo.synchronizationRules[0]).objectMappings) {
                foreach ($mapping in $objMapping.attributeMappings) {
                    foreach ($mappingValue in $mapping.source) {
                        Write-Output "SCIM Source ID $($mappingValue.name)"

                        $appsTesult += [PSCustomObject]@{
                            ObjectID     = $SPNId
                            AppID        = $appId
                            AppName      = $appDisplayName
                            NameIdFormat = ""
                            Name         = $($mapping.targetAttributeName)
                            AttributeID  = $($mapping.source[0]).expression   
                            Source       = "SCIM"
                            InnerSource  = $objMapping.sourceObjectName
                        }

                    }
                }                       
            }
        }
        catch {
            Write-Warning "appDisplayName: $appDisplayName, appID: $appId, SPNId: $SPNId"
            Write-Warning "Failed to fetch SCIM claims policy for URL: $appIDInfo"
            Write-Warning $_.Exception.Message
            Write-Warning $_.Exception.Response.Content
        }

        # Export the array to a CSV file
        $appsTesult | Export-Csv -Path "apps.csv" -NoTypeInformation -Append
                
    }
    else {
        Write-Output "Skipping entry with empty ID"
    }
}
