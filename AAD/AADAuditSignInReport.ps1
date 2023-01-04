<#
.SYNOPSIS
This is a script for extracting Azure Active Directory Sign In Logs / Audit Logs

.DESCRIPTION
Generate logs from Azure Active Directory using Graph SDK in some ways useful in SOC (Security Operations Center)

.PARAMETER 1
Beta (Access the Beta Version of Graph SDK)

.PARAMETER 2
Flag to indicate Audit Logs (A) or Sign Logs (Any string not equal to A)

.PARAMETER 3
Minutes in the past from the actual date to filter logs (Default 5 minutes)

.PARAMETER 4
Scope for the Graph Connection

.PARAMETER 5
Tenant ID (Optional for an access token)

.PARAMETER 6
Application ID (Optional for an access token)

.PARAMETER 7
.Secret del App Registrarion (Optional for an access token)

.EXAMPLE
PS> .\AADAuditSignInReport.ps1

.NOTES
@2022

.LINK
github.com/dvaid-alxeadner/AzurepwshUtils/tree/main/AAD

#>
param ($beta='N',$isAudit='N', [Int16]$minutes=5, $scope=$null, $tenantID=$null, $appId=$null, $secret=$null)
function Extract-JWT {
 
    [cmdletbinding()]
    param([Parameter(Mandatory=$true)][string]$token)
 
    #Validate as per https://tools.ietf.org/html/rfc7519
    #Access and ID tokens are fine, Refresh tokens will not work
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }

    #Header
    $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }
    Write-Verbose "Base64 encoded (padded) header:"
    Write-Verbose $tokenheader
    #Convert from Base64 encoded string to PSObject all at once
    Write-Verbose "Decoded header:"
    [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json | Format-List | Out-Default
 
    #Payload
    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
    Write-Verbose "Base64 encoded (padded) payoad:"
    Write-Verbose $tokenPayload
    #Convert to Byte array
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    #Convert to string array
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    Write-Verbose "Decoded array in JSON format:"
    Write-Verbose $tokenArray
    #Convert from JSON to PSObject
    $tokobj = $tokenArray | ConvertFrom-Json
    Write-Verbose "Decoded Payload:"
    
    return $tokobj
}

try {

    if ($tenantID -and $appId -and $secret) 
    {
        $body =  @{
            Grant_Type    = "client_credentials"
            Scope         = "https://graph.microsoft.com/.default"
            Client_Id     = $appId
            Client_Secret = $secret
        }

        $dateName=[int](Get-Date -UFormat %s -Millisecond 0)
        $tz=Get-TimeZone 
        $baseUTCOffset=$tz.BaseUtcOffset.ToString()

        $folder=Get-ChildItem -Path ".\" -Force

        ForEach($row in $folder)
        {
            if ($row.PSChildName -like "*.txt")
            {
                $accessFile=$row.PSChildName
                $file=Get-Content $accessFile
            }
        }

        if ($accessFile) 
        {
            $decoded=Extract-JWT $file.ToString()
            $expiration=$decoded.exp

            $datediff=$expiration-$dateName

            if ($datediff -lt 100) 
            {
                Remove-Item $accessFile
                $connection = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" -Method POST -Body $body
                $token = $connection.access_token
                $token | Out-File -FilePath ".\$dateName.txt"
            }
            else 
            {
                $token=$file.ToString()
            }
        }
        else 
        {
            $connection = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" -Method POST -Body $body
            $token = $connection.access_token
            $token | Out-File -FilePath ".\$dateName.txt"
        }
    }

    if ($beta -eq 'Y')
    {
        if ($scope) 
        {
            if ($token) 
            {
                Connect-MgGraph -AccessToken $token -Scopes $scope
                Select-MgProfile -Name "beta"
                Write-Host "Warning, you are using Graph SDK in Beta Version"
            }
            else
            {
                Connect-Graph -Scopes $scope
                Select-MgProfile -Name "beta"
                Write-Host "Warning, you are using Graph SDK in Beta Version"
            }
        }
        else
        {
            if ($token) 
            {
                Connect-MgGraph -AccessToken $token
                Select-MgProfile -Name "beta"
                Write-Host "Warning, you are using Graph SDK in Beta Version"
            }
            else 
            {
                Connect-Graph
                Select-MgProfile -Name "beta"
                Write-Host "Warning, you are using Graph SDK in Beta Version"
            }
        }
    }
    else 
    {
        if ($scope) 
        {
            if ($token) 
            {
                Connect-MgGraph -AccessToken $token -Scopes $scope
            }
            else 
            {
                Connect-Graph -Scopes $scope
            }
        }
        else 
        {
            if ($token) 
            {
                Connect-MgGraph -AccessToken $token
            }
            else 
            {
                Connect-Graph
            }
        }
    } 

    $outData = [System.Collections.Generic.List[Object]]::new()
    $contador=0
    $filternow=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mmZ")
    $filterge=(Get-Date).AddMinutes(-$minutes).ToUniversalTime().ToString("yyyy-MM-ddTHH:mmZ")

    if ($isAudit -eq 'A') {
        [array]$data=Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge $filterge and activityDateTime lt $filternow" | Select-Object Id, ActivityDateTime, ActivityDisplayName, AdditionalDetails, Category, CorrelationId, InitiatedBy, LoggedByService,OperationType, Result, ResultReason, TargetResources, userAgent

        ForEach ($rows in $data)
        {
            $contador++
            $id=$rows.Id
            $dateTime=Get-Date -Date $rows.ActivityDateTime -Format 'yyyy-MM-dd HH:mm:ss'
            $dateTime=($dateTime+" $baseUTCOffset").ToString()
            $activityName=$rows.ActivityDisplayName
            $additionalDetails=$rows.AdditionalDetails
            $auditDetailsJSON=$additionalDetails|ConvertTo-Json
            $auditMember=$auditDetailsJSON|ConvertFrom-Json
            if ($auditMember.Key -eq 'UserType') 
            {
                $userType=$auditMember.Value
            }
            else {
                $userType=$null
            }

            $category=$rows.Category
            $correlId=$rows.CorrelationId
            $initiadedBy=$rows.InitiatedBy
            $app=$initiadedBy.App
            $idApp=$app.AppId
            $appDisplayName=$app.DisplayName
            $appServicePrincipalId=$app.ServicePrincipalId

            $userPerform=$initiadedBy.User
            $upn=$userPerform.UserPrincipalName
            $idUser=$userPerform.Id
            $IPUser=$userPerform.IPAddress

            $loggedBy=$rows.LoggedByService
            $operationType=$rows.OperationType
            $result=$rows.Result
            $resultReason=$rows.ResultReason
            $targetResource=$rows.TargetResources

            ForEach($target in $targetResource)
            {
                if($target.UserPrincipalName)
                {
                    $upnTR=$target.UserPrincipalName
                }
                else {
                    $upnTR=$null
                }
            }

            $userAgent=$rows.UserAgent
            
            if ($upn -like "*.com.co" -or $upnTR -like "*.com.co") 
            {
                if ($upn -notlike "*.com.co") 
                {
                    $upn=$upnTR
                }
               
                $CustomData= [PSCustomObject][Ordered]@{
                    id=$id
                    datetime=$dateTime
                    activityName=$activityName
                    auditDetailJSON=$auditDetailsJSON
                    category=$category
                    correlationId=$correlId
                    appId=$idApp
                    appName=$appDisplayName
                    appServicePrincipalId=$appServicePrincipalId
                    userPrincipalName=$upn
                    userPrincipalNameTarget=$upnTR
                    userType=$userType
                    idUser=$idUser
                    IPAddressUser=$IPUser
                    loggedBy=$loggedBy
                    operationType=$operationType
                    result=$result
                    failureReason=$resultReason
                    userAgent=$userAgent
                }
                $outData.Add($CustomData)
            }
        }
        $OutData | Sort-Object {$_.datetime -as [string]} | Select-Object id, datetime, activityName, auditDetailJSON, category, correlationId, initiatedBy, appId, appName, appServicePrincipalId, userPrincipalName, userType, IPAddressUser, loggedBy, operationType, result, failureReason, userAgent | Out-GridView
    }
    else 
    {    
        [array]$data=Get-MgAuditLogSignIn -Filter "contains(userPrincipalName,'com.co')" | Select-Object Id, AppDisplayName, AppId, AppliedConditionalAccessPolicies, AuthenticationContextClassReferences,AuthenticationDetails,AuthenticationMethodsUsed, AuthenticationProcessingDetails,AuthenticationProtocol, AuthenticationRequirement, AuthenticationRequirementPolicies, AutonomousSystemNumber, AzureResourceId, ClientAppUsed, ClientCredentialType, ConditionalAccessStatus, CorrelationId, crossTenantAccessType, CreatedDateTime, DeviceDetail, FederatedCredentialId, FlaggedForReview, HomeTenantId, HomeTenantName, IncomingTokenType, IPAddress, IPAddressFromResourceProvider, IsInteractive, IsTenantRestricted, Location, NetworkLocationDetails, OriginalRequestId, PrivateLinkDetails, ProcessingTimeInMilliseconds, ResourceId, ResourceDisplayName, ResourceServicePrincipalId, ResourceTenantId, RiskDetail, RiskEventTypesV2, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, ServicePrincipalId, ServicePrincipalCredentialKeyId, ServicePrincipalCredentialThumbprint, ServicePrincipalName, SessionLifetimePolicies, SignInEventTypes, SignInIdentifier, SignInIdentifierType, Status, TokenIssuerName, TokenIssuerType, UniqueTokenIdentifier, UserAgent, UserId, UserDisplayName, UserPrincipalName, UserType

        ForEach ($rows in $data)
        {
            $id=$rows.Id
            $appName=$rows.AppDisplayName
            $appId=$rows.AppId
            $appliedCAPolicies=$rows.AppliedConditionalAccessPolicies.Count
            $authContextClass=$rows.AuthenticationContextClassReferences.Count

            $authDetails=$rows.AuthenticationDetails
            $authenticationDetailsMethod=$authDetails.AuthenticationMethod
            $authenticationDetailsMethodJSON=$authenticationDetailsMethod|ConvertTo-Json
            $authenticationDetailsStep=$authDetails.AuthenticationStepRequirement
            $authenticationDetailsStepResult=$authDetails.AuthenticationStepResultDetail
            $authenticationDetailsStepResultJSON=$authenticationDetailsStepResult|ConvertTo-Json
            
            $authMethods=$rows.AuthenticationMethodsUsed.Count
            $authProcesssing=$rows.AuthenticationProcessingDetails.Count
            $authProtocol=$rows.AuthenticationProtocol
            $authRequirement=$rows.AuthenticationRequirement
            $authRequirementPolicies=$rows.AuthenticationRequirementPolicies.Count
            $autonomousSystem=$rows.AutonomousSystemNumber

            $azureResourceId=$rows.AzureResourceId
            $clientApp=$rows.ClientAppUsed
            $clientCredentialType=$rows.ClientCredentialType
            $conditionalAccessStatus=$rows.ConditionalAccessStatus
            $correlId=$rows.CorrelationId
            $dateTime=$rows.CreatedDateTime
            $crossTenantAccess=$rows.CrossTenantAccessType

            $deviceDetail=$rows.DeviceDetail
            $Browser=$deviceDetail.Browser
            $IsManaged=$deviceDetail.IsManaged
            $OS=$deviceDetail.OperatingSystem

            $federatedClientId=$rows.FederatedCredentialId
            $flaggedForReview=$rows.FlaggedForReview
            $homeTenantId=$rows.HomeTenantId
            $homeTenantName=$rows.HomeTenantName
            $incomingTokenType=$rows.IncomingTokenType
            $ipAddress=$rows.IPAddress
            $ipAddressFromResProv=$rows.IPAddressFromResourceProvider
            $isInteractive=$rows.IsInteractive
            $isTenantRestricted=$rows.IsTenantRestricted
            
            $location=$rows.Location
            $coordinates=$location.GeoCoordinates
            $city=$location.City
            $countryCode=$location.CountryOrRegion
            $geoState=$location.State
            $latitude=$coordinates.Latitude
            $longitude=$coordinates.Longitude

            $networkDetails=$rows.NetworkLocationDetails
            $networkDetailsJson=$networkDetails|ConvertTo-Json
            
            $originalReqId=$rows.OriginalRequestId
            $privateLinkDetails=$rows.PrivateLinkDetails
            $proccessTime=$rows.ProcessingTimeInMilliseconds
            $resourceId=$rows.ResourceId
            $resourceName=$rows.ResourceDisplayName
            $resourceServicePrincipalId=$rows.ResourceServicePrincipalId
            $resourceTenantId=$rows.ResourceTenantId
            $riskDetail=$rows.RiskDetail
            $riskEventV2=$rows.RiskEventTypesV2 
            $riskLevelAgg=$rows.RiskLevelAggregated
            $riskLevelDurSignIn=$rows.RiskLevelDuringSignIn
            $riskState=$rows.RiskState
            $servicePrincialCredKeyId=$rows.ServicePrincipalCredentialKeyId
            $servicePrincipalCredThumb=$rows.ServicePrincipalCredentialThumbprint
            $servicePrincipalId=$rows.ServicePrincipalId
            $servicePrincipalName=$rows.ServicePrincipalName

            $sessionLifeTimePolicies=$rows.SessionLifetimePolicies
            $sessionDetail=$sessionLifeTimePolicies.Detail
            $sessionExpiration=$sessionLifeTimePolicies.ExpirationRequirement

            $singInEventTypes=$rows.SignInEventTypes
            $singInEventTypesJSON=$singInEventTypes|ConvertTo-Json

            $singInIdentifier=$rows.SignInIdentifier
            $singInIdentifierType=$rows.SignInIdentifierType

            $status=$rows.Status
            $statusDetails=$status.AdditionalDetails
            $statusErrorCode=$status.ErrorCode
            $statusFailure=$status.FailureReason

            $tokenIssuerName=$rows.TokenIssuerName
            $tokenIssuerType=$rows.TokenIssuerType
            $uniqueTokenId=$rows.UniqueTokenIdentifier
            $userAgent=$rows.UserAgent
            $userId=$rows.UserId
            $userDisplayName=$rows.UserDisplayName
            $upn=$rows.UserPrincipalName
            $userType=$rows.UserType

            $ErrorCode = ($rows | Select-Object -ExpandProperty Status).ErrorCode
            $FailureReason = ($rows | Select-Object -ExpandProperty Status).FailureReason

            $CustomData= [PSCustomObject][Ordered]@{
                id=$id
                appName=$appName
                appId=$appId
                authenticationDetailsMethod=$authenticationDetailsMethodJSON
                authenticationStepResult=$authenticationDetailsStepResultJSON
                authenticationProtocol=$authProtocol
                authenticationRequirement=$authRequirement
                clientApp=$clientApp
                clientCredentialType=$clientCredentialType
                conditionalAccessStatus=$conditionalAccessStatus
                correlationId=$correlId
                datetime=$dateTime
                crossTenantAccess=$crossTenantAccess
                Browser=$Browser
                OS=$OS
                incomingTokenType=$incomingTokenType
                homeTenantId=$homeTenantId
                ipAdrress=$ipAddress
                isInteractive=$isInteractive
                isTenantRestricted=$isTenantRestricted
                countryCode=$countryCode
                state=$geoState
                city=$city
                latitude=$latitude
                longitud=$longitude

                networkDetails=$networkDetailsJson

                processTime=$proccessTime
                resourceId=$resourceId
                resourceName=$resourceName
                resourceServicePrincipalId=$resourceServicePrincipalId
                resourceTenantId=$resourceTenantId
                riskDetail=$riskDetail
                riskLevelAggredated=$riskLevelAgg
                riskLevelDuringSignIn=$riskLevelDurSignIn
                riskState=$riskState
                servicePrincipalCredentiaKeylId=$servicePrincialCredKeyId
                servicePrincipalCredentialThumb=$servicePrincipalCredThumb
                servicePrincipalId=$servicePrincipalId
                servicePrincipalName=$servicePrincipalName
                sessionPolicyDetail=$sessionDetail
                sessionPolicyExpiration=$sessionExpiration
                signInEventTypes=$singInEventTypesJSON
                status=$statusDetails
                statusErrorCode=$statusErrorCode
                statusFailure=$statusFailure
                tokenIssuerName=$tokenIssuerName
                tokenIssuerType=$tokenIssuerType
                uniqueTokenId=$uniqueTokenId
                userAgent=$userAgent
                userId=$userId
                userDisplayName=$userDisplayName
                userPrincipalName=$upn
                userType=$userType
            }
            $OutData.Add($CustomData)
        }
    }
    
    $OutData | Sort-Object {$_.Timestamp -as [datetime]} | Select-Object Timestamp, User, TenantName, Resource, AppName | Out-GridView
    
    Write-Host $contador
}
catch {
    Write-Output $_.Exception.GetType().FullName, $_.Exception.Message
    Write-Host "Error please report in https://github.com/dvaid-alxeadner/AzurepwshUtils"
    exit 
}
