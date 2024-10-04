# Define the URL
$url = "https://graph.microsoft.com/beta/servicePrincipals/7acdd580-a94c-4741-a265-30d5aa039203"
# $url = "https://graph.microsoft.com/beta/servicePrincipals"
# $url = "https://graph.microsoft.com/v1.0/applications/2d72b04b-f527-48b6-8e4c-336569e90317"


# Define the access token (replace with your actual token)
$accessToken = ""
# Set the headers
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# Initialize variables for pagination
$allResults = @()
$nextPageUrl = $url

# Loop to fetch all pages
while ($nextPageUrl) {
    # Fetch the current page
    $response = Invoke-RestMethod -Uri $nextPageUrl -Headers $headers -Method Get
    
    # Add the current page results to the collection
    $allResults += $response
    
    # Check if there is a next page
    if ($response.'@odata.nextLink') {
        $nextPageUrl = $response.'@odata.nextLink'
    }
    else {
        $nextPageUrl = $null
    }
}

# Display the results and fetch claims policies
$allResults | ForEach-Object {
    if (-not [string]::IsNullOrEmpty($_.id)) {
        $SPNId = $_.id
        $appId = $_.appId
        $appDisplayName = $_.displayName

        Write-Output $_.displayName, $_.id

        # Correct URL for fetching claims policy
        $claimsPolicyUrl = "https://graph.microsoft.com/beta/servicePrincipals/$($_.id)/claimsPolicy"
        Write-Output "Searching for claims policy at $claimsPolicyUrl"

        try {
            # Make the request for claims policy
            $responseClaims = Invoke-RestMethod -Uri $claimsPolicyUrl -Headers $headers -Method Get
            foreach ($claim in $responseClaims) {
                foreach ($config in $claim.claims) {
                    foreach ($value in $config.configurations) {
                        Write-Output "Object ID $SPNId, AppName $appDisplayName,  nameIdFormat $($config.nameIdFormat), name $($config.name) , ID: $($value.attribute.id), Source: $($value.attribute.source)"
                    }
                }
            }
        }
        catch {
            Write-Error "Failed to fetch claims policy for URL: $claimsPolicyUrl"
            Write-Error $_.Exception.Message
            Write-Error $_.Exception.Response.Content
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
            Write-Error "Failed to fetch claims policy for URL: $appIDInfo"
            Write-Error $_.Exception.Message
            Write-Error $_.Exception.Response.Content
        }        
    }
    else {
        Write-Output "Skipping entry with empty ID"
    }
}