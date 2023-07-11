# GetAdAcl

Check ad acl by using distinguishedname, just for fun.

## Get Acl of a domain object

`Get-AdAcl -dn $UserDn`

The output noteproperty contains: 

```
AccessControlType
ActiveDirectoryRights
IdentityReference
InheritanceFlags
InheritanceType
InheritedObjectType
Isinherited
ObjectFlags
ObjectType
PropagationFlags
sAMaccountName
```

![Get-AdAcl](README/Screenshot2023-07-11%2016.44.16.jpg)

## Check DCSync privileged rights

```
Get-AdAcl -dn "DC=yourdomain,DC=com" |? objecttype -Match "replicating" | ft -auto
```
