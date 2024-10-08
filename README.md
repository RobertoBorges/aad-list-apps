# Sample project to get all Claims attributes from Entra ID

This includes claims from SAML, OpenID Connect and SCIM

You will be required to have an access token with the proper permissions to access the Entra ID API.

You can use the code itself to get one access token, and I presume the App ID for Graph API still:

14d82eec-204b-4c2f-b7e8-296a70dab67e

The easiest way to get started if to enter a list of Apps you are looking for on the file AppsToList.csv following the example:

```csv
"ObjectID","AppID","AppName","nameIdFormat","name","ID","Source"
"40584da2-....","a9f97dcd-...","DemoSCIMApp","emailAddress",,"userprincipalname","user"
```
