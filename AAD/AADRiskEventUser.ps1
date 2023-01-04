<#
.SYNOPSIS
This is a script for extracting Azure Active Directory Risky Events / Risky Users

.DESCRIPTION
Generate logs from Azure Active Directory using Graph SDK in some ways useful in SOC (Security Operations Center)

.PARAMETER 1
Beta (Access the Beta Version of Graph SDK)

.PARAMETER 2
Flag to indicate Risky Events (E) or Risky Users (Any string not equal to E)

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
PS> .\AADRiskEventUser.ps1

.NOTES
@2022

.LINK
github.com/dvaid-alxeadner/AzurepwshUtils/tree/main/AAD

#>
param ($beta='N',$isEvent='N', [Int16]$minutes=5, $scope=$null, $tenantID=$null, $appId=$null, $secret=$null)
function Extract-JWT {
    # https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
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

            if ($datediff -lt 300) 
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
                Connect-MgGraph -AccessToken $token
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
        if ($token) 
        {
            Connect-MgGraph -AccessToken $token
        }
        else 
        {
            Connect-Graph
        }
    } 

    $outData = [System.Collections.Generic.List[Object]]::new()
    $contador=0
    $filternow=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mmZ")
    $filterge=(Get-Date).AddMinutes(-$minutes).ToUniversalTime().ToString("yyyy-MM-ddTHH:mmZ")

    if ($isEvent -eq 'E') {

        [array]$data=Get-MgRiskDetection -Filter "activityDateTime ge $filterge and activityDateTime lt $filternow"

        ForEach ($rows in $data)
        {
            $contador++
            $userAgent=$null
            $riskReason=$null
            $id=$rows.Id
            $dateTime=Get-Date -Date $rows.ActivityDateTime -Format 'yyyy-MM-dd HH:mm:ss'
            $dateTime=($dateTime+" $baseUTCOffset").ToString()
            $activityName=$rows.Activity
            $additionalDetails=$rows.AdditionalInfo|ConvertFrom-Json

            ForEach ($k in $additionalDetails)
            {
                if ($k.key -eq 'userAgent') 
                {
                    $userAgent=$k.Value.ToString()
                }

                if ($k.key -eq 'riskReasons') 
                {
                    $riskReason=$k.Value
                }
            }

            $correlId=$rows.CorrelationId

            $detectdateTime=Get-Date -Date $rows.DetectedDateTime -Format 'yyyy-MM-dd HH:mm:ss'
            $detectdateTime=($detectdateTime+" $baseUTCOffset").ToString()
            $detectionTiming=$rows.DetectionTimingType
            $IPUser=$rows.IPAddress
            $lastupdatedateTime=Get-Date -Date $rows.LastUpdatedDateTime -Format 'yyyy-MM-dd HH:mm:ss'
            $lastupdatedateTime=($lastupdatedateTime+" $baseUTCOffset").ToString()

            $location=$rows.Location
            $coordinates=$location.GeoCoordinates
            $city=$location.City
            $countryCode=$location.CountryOrRegion
            $geoState=$location.State
            $latitude=$coordinates.Latitude
            $longitude=$coordinates.Longitude
            
            $requestId=$rows.RequestId

            $riskDetail=$rows.RiskDetail
            $riskEventType=$rows.RiskEventType
            $riskLevel=$rows.RiskLevel
            $riskState=$rows.RiskState
            $source=$rows.Source
            $tokenIssuer=$rows.TokenIssuerType
            $idUser=$rows.UserId
            $userName=$rows.UserDisplayName
            $upn=$rows.UserPrincipalName

            $additionalProperties=$rows.AdditionalProperties
            
            if ($upn -like "*.com.co") 
            {               
                $CustomData= [PSCustomObject][Ordered]@{
                    id=$id
                    datetime=$dateTime
                    activityName=$activityName
                    correlationId=$correlId
                    detectedDateTime=$detectdateTime
                    detectionTimingType=$detectionTiming
                    IPUser=$IPUser
                    lastUpdateTime=$lastupdatedateTime
                    city=$city
                    countryCode=$countryCode
                    geoState=$geoState
                    latitude=$latitude
                    longitude=$longitude
                    requestId=$requestId
                    riskDetail=$riskDetail
                    risklevel=$riskLevel
                    riskReason=$riskReason
                    riskEventType=$riskEventType
                    riskState=$riskState
                    source=$source
                    tokenIssuer=$tokenIssuer
                    idUser=$idUser
                    userPrincipalName=$upn
                    userDisplayName=$userName
                    userType=$userType                    
                    userAgent=$userAgent
                }
                $outData.Add($CustomData)
            }
        }
        $OutData | Sort-Object {$_.datetime -as [string]} | Select-Object id, datetime, activityName, correlationId, detectedDateTime, detectionTimingType, IPUser, lastUpdateTime, city, countryCode, geoState, latitude, longitude, requestId, riskDetail, riskReason, riskEventType, riskState, source, tokenIssuer, idUser, userPrincipalName, userDisplayName, userType, userAgent | Out-GridView
    }
    else 
    {    
        [array]$data=Get-MgRiskyUser -Filter "contains(userPrincipalName,'com.co') and RiskLastUpdatedDateTime ge $filterge and RiskLastUpdatedDateTime lt $filternow" 

        ForEach ($rows in $data)
        {
            $id=$rows.Id
            $isDeleted=$rows.IsDeleted
            $isProcessing=$rows.IsProcessing
            $riskLastUpdate=Get-Date -Date $rows.RiskLastUpdatedDateTime -Format 'yyyy-MM-dd HH:mm:ss'
            $riskLastUpdate=($riskLastUpdate+" $baseUTCOffset").ToString()
            $riskDetail=$rows.RiskDetail
            $riskLevel=$rows.RiskLevel
            $riskState=$rows.RiskState
            $userName=$rows.UserDisplayName
            $upn=$rows.UserPrincipalName

            $additionalProperties=$rows.AdditionalProperties

            $CustomData= [PSCustomObject][Ordered]@{
                id=$id
                isDeleted=$isDeleted
                isProcessing=$isProcessing
                riskLastUpdate=$riskLastUpdate
                riskDetail=$riskDetail
                riskLevel=$riskLevel
                riskState=$riskState
                userDisplayName=$userName
                userPrincipalName=$upn
            }
            $OutData.Add($CustomData)
        }
        $OutData | Sort-Object {$_.datetime -as [string]} | Select-Object id, isDeleted, IsProcessing, riskLastUpdate, riskDetail, riskLevel, riskState, userDisplayName, userPrincipalName | Out-GridView
    }
    
    Write-Host $contador
}
catch {
    Write-Output $_.Exception.GetType().FullName, $_.Exception.Message
    Write-Host "Error please report in https://github.com/dvaid-alxeadner/AzurepwshUtils"
    exit 
}
