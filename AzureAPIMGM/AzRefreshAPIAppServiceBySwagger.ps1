param ($SubscriptionId='aaaaaaaa-bbbb-cccc-eeee-fffffffffff', $TenantPosto='aaaaaaaa-bbbb-cccc-eeee-fffffffffff', $rgName='RG_XXX_YYY', $apiMGMService='APIMGMTXXX', $apiName, $apiPrefix, $apiProductId, $ServiceURL, $HttpMethods = 'NO', $frontEndUrl, $JWT = 'NO', $JWTvalURL = 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration', $audience ='NO', $ticket, $BackendID='NO', $ApiType='Swagger', $wsdlBackend='False')

if (($frontEndUrl -as [System.URI]).AbsoluteURI)
{
    Write-Host $frontEndUrl" is the only URI in CORS policies?"
}
else 
{
    $frontEndUrl='*'
}

if ($ApiType -eq 'Swagger')
{
    if ( $ServiceURL.IndexOf("/swagger") -ne -1 )
    {
        $index = $ServiceURL.IndexOf("/swagger")
        $backend = $ServiceURL.SubString(0,$index)
    }
    elseif ($ServiceURL.IndexOf("/openapi.json") -ne -1) 
    {
        $index = $ServiceURL.IndexOf("/openapi.json")
        $backend = $ServiceURL.SubString(0,$index)  
    }
    else
    {
        Write-Host "Invalid Backend" 
        exit 
    }
}
elseif ($ApiType -eq 'WSDL')
{
    if (Test-Path -Path $ServiceURL -PathType leaf) 
    {
        $backend=[Security.SecurityElement]::Escape($wsdlBackend)
    
        $type='soap'
    }
    elseif( $ServiceURL.IndexOf("?wsdl") -ne -1 )
    {
        Write-Host "URL WSDL File"
        exit
    }
    else
    {
        Write-Host "Invalid WSDL File"
        exit
    }
}
elseif ($ApiType -eq 'WSDL2JSON')
{
    if (Test-Path -Path $ServiceURL -PathType leaf) 
    {
        $backend=[Security.SecurityElement]::Escape($wsdlBackend)
        $type='http'
    }
}
else 
{
    Write-Host "API Type is not supported yet" 
    exit 
}

Write-Host $backend" is the right backend for the API?"

if ($HttpMethods -eq 'GPD')
{
    if ($JWT -eq 'NO')
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>DELETE</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>DELETE</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
    else 
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>DELETE</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>DELETE</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
}
elseif ($HttpMethods -eq 'GPU')
{
    if ($JWT -eq 'NO')
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>PUT</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>PUT</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
    else 
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>PUT</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>PUT</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
}
elseif ($HttpMethods -eq 'GPDU') 
{
    if ($JWT -eq 'NO')
    {
        if ($BackendID -eq 'NO')
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>DELETE</method>
                        <method>PUT</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>DELETE</method>
                        <method>PUT</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
    else 
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>DELETE</method>
                        <method>PUT</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>DELETE</method>
                        <method>PUT</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
}
elseif ($HttpMethods -eq 'GPDUA')
{
    if ($JWT -eq 'NO')
    {
        if ($BackendID -eq 'NO')
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>DELETE</method>
                        <method>PUT</method>
                        <method>PATCH</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>DELETE</method>
                        <method>PUT</method>
                        <method>PATCH</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
    else 
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>DELETE</method>
                        <method>PUT</method>
                        <method>PATCH</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                        <method>DELETE</method>
                        <method>PUT</method>
                        <method>PATCH</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
}
elseif ($HttpMethods -eq 'GP') 
{
    if ($JWT -eq 'NO')
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
    else 
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                        <method>POST</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
}
elseif ($HttpMethods -eq 'P') 
{
    if ($JWT -eq 'NO')
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>POST</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>POST</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
    else 
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>POST</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>POST</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
}
elseif ($HttpMethods -eq 'G') 
{
    if ($JWT -eq 'NO')
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
    else 
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <cors>
                    <allowed-origins>
                        <origin>'+$frontEndUrl+'</origin>
                    </allowed-origins>
                    <allowed-methods>
                        <method>GET</method>
                    </allowed-methods>
                    <allowed-headers>
                        <header>*</header>
                    </allowed-headers>
                </cors>
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                <audiences>
                    <audience>'+$audience+'</audience>
                </audiences>
                </validate-jwt>
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
}
else 
{    
    if ($JWT -eq 'NO')
    {
        if ($BackendID -eq 'NO') 
        {   
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <set-backend-service base-url="'+$backend+'" />
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <set-backend-service backend-id="'+$BackendID+'" />
            </inbound>
            </policies>'
        }
    }
    else 
    {
        if ($BackendID -eq 'NO') 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <set-backend-service base-url="'+$backend+'" />
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <openid-config url="'+$JWTvalURL+'" />
                </validate-jwt>
            </inbound>
            </policies>'
        }
        else 
        {
            $InboundPolicy = '<policies>
            <inbound>
                <base />
                <set-backend-service base-url="'+$backend+'" />
                <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid." require-expiration-time="true" require-scheme="Bearer" require-signed-tokens="true">
                <set-backend-service backend-id="'+$BackendID+'" />
                </validate-jwt>
            </inbound>
            </policies>'
        }
    }
}

try {
    
    # Connect To Azure (Interactive Login)
    $Connection = Connect-AzAccount -Tenant $TenantPosto -SubscriptionId $SubscriptionId

    if ($Connection)
    {

        # Get Context to API Management Resource Group and API Management Service
        $Context = New-AzApiManagementContext -resourcegroup $rgName -servicename $apiMGMService
        # Get API information $api.ApiId contains the API id

        $api=Get-AzApiManagementApi -Context $Context -Name $apiName

        Write-Output $api
        Write-Output "`a"
        # Remove API and asks for confirmation
        Remove-AzApiManagementApi -Context $Context -ApiId $api.ApiId -Confirm
    
        # Import the API from Swagger URL 
            
        if ($ApiType -eq 'Swagger')
        {            
            $newAPi=Import-AzApiManagementApi -Context $Context -ApiId $apiName.ToLower() -SpecificationFormat 'OpenApi' -SpecificationUrl $ServiceURL -Path $apiPrefix
        }
        elseif ($ApiType -eq 'WSDL') 
        {
            $newAPi=Import-AzApiManagementApi -Context $Context -ApiId $apiName.ToLower() -ApiType $type -SpecificationFormat 'WSDL' -SpecificationPath $ServiceURL -Path $apiPrefix -WsdlServiceName $wsdlName -WsdlEndpointName $wsdlEndPointName
        }
        else 
        {
            Write-Host "API Type is not supported yet for creation" 
            exit 
        }

        $dt=Get-Date

        if (-not $newApi) 
        {

            Write-Host "Impossible to create API "$apiName 
        }
        else 
        {
            Set-AzApiManagementApi -Context $Context -ApiId $apiName.ToLower() -Protocols @('https') -SubscriptionRequired -Name $apiName -Description $apiName' Ticket:'$ticket' Refreshed by AzRefreshAPIBySwagger.ps1 on '$dt 
            Write-Output $newApi

            # Writes the inbound Policy defined for the API
            Set-AzApiManagementPolicy -Context $Context -ApiId $newApi.ApiId -Policy $InboundPolicy
            Add-AzApiManagementApiToProduct -Context $Context -ProductId $apiProductId -ApiId $apiName.ToLower()
        }
    }
    else
    {
        Write-Host "Cannot Continue - Invalid Login" 
        exit 
    }
}
Catch
{
    Write-Output $_.Exception.GetType().FullName, $_.Exception.Message
    Write-Host "Error please report in https://github.com/dvaid-alxeadner/AzurepwshUtils" 
    exit 
}