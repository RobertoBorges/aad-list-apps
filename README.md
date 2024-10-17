# Powershel script to get all claims attributes from Entra ID

## Introduction

Claims attributes are the attributes that are sent to the applications when a user logs in. This script will get all the claims attributes from Entra ID for a list of applications.

Sometimes, we need to know what claims are being sent to an application, and this script will help you to get all the claims attributes from Entra ID for a list of applications.

This is very usefull for impact analysis, when you need to know what claims are being sent to an application.

This script will includes claims from Access Token, SAML, OpenID Connect and SCIM

## Prerequisites

Global Administrator or Application Administrator role in Azure AD

PowerShell 5.1 or later

## Getting Started

This script uses MSAL to get a token from you user, that will be used to get the claims from the Entra ID API.

If is the first time you are using GraphAPI app, the authentication will ask you to authenticate and give consent to the app. This is a one time operation.

For information, we use the following app on Enterprise Applications to get tokens:
14d82eec-204b-4c2f-b7e8-296a70dab67e

The easiest way to get started is to enter a list of Apps you are scanning on the file AppsToList.csv following the example:

```csv
"ObjectID","AppID","AppName","nameIdFormat","name","ID","Source"
"40584da2-....","a9f97dcd-...","DemoSCIMApp","emailAddress",,"userprincipalname","user"
```

or you can use the following variables to set the get of apps and the access token automatically:

```powershell
# Set to true if you want to acquire a fresh token
$getFreshToken = $false

# Set to true if you want to generate the list of apps to scan
$generateListToScan = $false
```

This app can be used in general to assess the claims of any app, but it is particularly useful for SCIM apps, as it will show the claims that are being sent to the app.

You can use this later to follow how your applications are consuming the claims on Entra ID.

Any feedback and pull requests are welcome.
