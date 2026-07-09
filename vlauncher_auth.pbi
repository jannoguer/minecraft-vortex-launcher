; Microsoft (official) account authentication for Vortex Launcher.
;
; Implements the OAuth 2.0 device code flow and the token chain required
; by Minecraft: Java Edition:
;   device code -> MSA token -> Xbox Live token -> XSTS token -> Minecraft token -> game profile
;
; The client ID must belong to an Azure application that Mojang has approved
; for the Minecraft services API, otherwise login_with_xbox is rejected.
; See https://help.minecraft.net/hc/en-us/articles/16254801392141
; The ID can be overridden with the MsaClientId key in vortex_launcher.conf.

#MsaClientIdDefault = ""
#MsaScope = "XboxLive.signin offline_access"
#MsaDeviceCodeUrl = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
#MsaTokenUrl = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
#MsaXblAuthUrl = "https://user.auth.xboxlive.com/user/authenticate"
#MsaXstsAuthUrl = "https://xsts.auth.xboxlive.com/xsts/authorize"
#MsaMinecraftLoginUrl = "https://api.minecraftservices.com/authentication/login_with_xbox"
#MsaMinecraftProfileUrl = "https://api.minecraftservices.com/minecraft/profile"

Global.s msaPlayerName, msaUuid, msaAccessToken, msaXuid
Global.s msaLastError
Global.i msaHttpStatus

Declare.s msaClientId()
Declare.s msaHttpRequest(verb.i, url.s, body.s = "", contentType.s = "", bearer.s = "")
Declare.s msaJsonString(jsonString.s, key.s)
Declare.q msaJsonInteger(jsonString.s, key.s)
Declare.s msaJwtPayload(jwt.s)
Declare msaOpenBrowser(url.s)
Declare.i msaXboxChain(msaToken.s)
Declare.i msaEnsureLogin()
Declare.i msaLoginInteractive()
Declare msaLogout()
Declare.s msaStatusText()

Procedure.s msaClientId()
  ProcedureReturn ReadPreferenceString("MsaClientId", #MsaClientIdDefault)
EndProcedure

Procedure.s msaHttpRequest(verb.i, url.s, body.s = "", contentType.s = "", bearer.s = "")
  Protected NewMap headers.s()
  Protected.i request
  Protected.s response

  headers("Accept") = "application/json"

  If contentType <> ""
    headers("Content-Type") = contentType
  EndIf

  If bearer <> ""
    headers("Authorization") = "Bearer " + bearer
  EndIf

  msaHttpStatus = 0
  request = HTTPRequest(verb, url, body, 0, headers())

  If request
    msaHttpStatus = Val(HTTPInfo(request, #PB_HTTP_StatusCode))
    response = HTTPInfo(request, #PB_HTTP_Response)

    FinishHTTP(request)
  EndIf

  ProcedureReturn response
EndProcedure

Procedure.s msaJsonString(jsonString.s, key.s)
  Protected.i json, member
  Protected.s value

  json = ParseJSON(#PB_Any, jsonString)

  If json
    member = GetJSONMember(JSONValue(json), key)

    If member And JSONType(member) = #PB_JSON_String
      value = GetJSONString(member)
    EndIf

    FreeJSON(json)
  EndIf

  ProcedureReturn value
EndProcedure

Procedure.q msaJsonInteger(jsonString.s, key.s)
  Protected.i json, member
  Protected.q value

  json = ParseJSON(#PB_Any, jsonString)

  If json
    member = GetJSONMember(JSONValue(json), key)

    If member And JSONType(member) = #PB_JSON_Number
      value = GetJSONInteger(member)
    EndIf

    FreeJSON(json)
  EndIf

  ProcedureReturn value
EndProcedure

Procedure.s msaJwtPayload(jwt.s)
  Protected.s payload = StringField(jwt, 2, ".")
  Protected.s decoded
  Protected *buffer

  payload = ReplaceString(payload, "-", "+")
  payload = ReplaceString(payload, "_", "/")

  While Len(payload) % 4
    payload + "="
  Wend

  *buffer = AllocateMemory(Len(payload) + 1)

  If *buffer
    If Base64Decoder(payload, *buffer, MemorySize(*buffer) - 1)
      decoded = PeekS(*buffer, -1, #PB_UTF8)
    EndIf

    FreeMemory(*buffer)
  EndIf

  ProcedureReturn decoded
EndProcedure

Procedure msaOpenBrowser(url.s)
  CompilerSelect #PB_Compiler_OS
    CompilerCase #PB_OS_Windows
      RunProgram(url)
    CompilerCase #PB_OS_Linux
      RunProgram("xdg-open", url, "")
    CompilerCase #PB_OS_MacOS
      RunProgram("open", url, "")
  CompilerEndSelect
EndProcedure

Procedure.i msaXboxChain(msaToken.s)
  Protected.i requestJson, root, properties, userTokens, json, member, claims, xui
  Protected.s requestBody, response, xblToken, userHash, xstsToken, jwtPayload
  Protected.q xErr

  ; Xbox Live authentication
  requestJson = CreateJSON(#PB_Any)
  root = SetJSONObject(JSONValue(requestJson))
  properties = SetJSONObject(AddJSONMember(root, "Properties"))
  SetJSONString(AddJSONMember(properties, "AuthMethod"), "RPS")
  SetJSONString(AddJSONMember(properties, "SiteName"), "user.auth.xboxlive.com")
  SetJSONString(AddJSONMember(properties, "RpsTicket"), "d=" + msaToken)
  SetJSONString(AddJSONMember(root, "RelyingParty"), "http://auth.xboxlive.com")
  SetJSONString(AddJSONMember(root, "TokenType"), "JWT")
  requestBody = ComposeJSON(requestJson)
  FreeJSON(requestJson)

  response = msaHttpRequest(#PB_HTTP_Post, #MsaXblAuthUrl, requestBody, "application/json")

  json = ParseJSON(#PB_Any, response)

  If json
    root = JSONValue(json)
    member = GetJSONMember(root, "Token")

    If member
      xblToken = GetJSONString(member)
    EndIf

    claims = GetJSONMember(root, "DisplayClaims")

    If claims
      xui = GetJSONMember(claims, "xui")

      If xui And JSONArraySize(xui) > 0
        member = GetJSONMember(GetJSONElement(xui, 0), "uhs")

        If member
          userHash = GetJSONString(member)
        EndIf
      EndIf
    EndIf

    FreeJSON(json)
  EndIf

  If xblToken = "" Or userHash = ""
    msaLastError = "Xbox Live authentication failed (HTTP " + Str(msaHttpStatus) + ")."
    ProcedureReturn 0
  EndIf

  ; XSTS authorization
  requestJson = CreateJSON(#PB_Any)
  root = SetJSONObject(JSONValue(requestJson))
  properties = SetJSONObject(AddJSONMember(root, "Properties"))
  SetJSONString(AddJSONMember(properties, "SandboxId"), "RETAIL")
  userTokens = SetJSONArray(AddJSONMember(properties, "UserTokens"))
  SetJSONString(AddJSONElement(userTokens), xblToken)
  SetJSONString(AddJSONMember(root, "RelyingParty"), "rp://api.minecraftservices.com/")
  SetJSONString(AddJSONMember(root, "TokenType"), "JWT")
  requestBody = ComposeJSON(requestJson)
  FreeJSON(requestJson)

  response = msaHttpRequest(#PB_HTTP_Post, #MsaXstsAuthUrl, requestBody, "application/json")
  xstsToken = msaJsonString(response, "Token")

  If xstsToken = ""
    xErr = msaJsonInteger(response, "XErr")

    If xErr = 2148916233
      msaLastError = "This Microsoft account has no Xbox profile. Log in at xbox.com once to create it."
    ElseIf xErr = 2148916238
      msaLastError = "This is a child account. It must be added to a Microsoft family to play."
    Else
      msaLastError = "XSTS authorization failed (HTTP " + Str(msaHttpStatus) + ", XErr " + Str(xErr) + ")."
    EndIf

    ProcedureReturn 0
  EndIf

  ; Minecraft services login
  requestJson = CreateJSON(#PB_Any)
  root = SetJSONObject(JSONValue(requestJson))
  SetJSONString(AddJSONMember(root, "identityToken"), "XBL3.0 x=" + userHash + ";" + xstsToken)
  requestBody = ComposeJSON(requestJson)
  FreeJSON(requestJson)

  response = msaHttpRequest(#PB_HTTP_Post, #MsaMinecraftLoginUrl, requestBody, "application/json")
  msaAccessToken = msaJsonString(response, "access_token")

  If msaAccessToken = ""
    msaLastError = "Minecraft login failed (HTTP " + Str(msaHttpStatus) + "). The launcher client ID may not be approved by Mojang."
    ProcedureReturn 0
  EndIf

  ; auth_xuid is stored in the payload of the Minecraft access token
  jwtPayload = msaJwtPayload(msaAccessToken)
  msaXuid = msaJsonString(jwtPayload, "xuid")

  If msaXuid = ""
    msaXuid = "0000"
  EndIf

  ; Game profile (responds with 404 if the account doesn't own the game)
  response = msaHttpRequest(#PB_HTTP_Get, #MsaMinecraftProfileUrl, "", "", msaAccessToken)
  msaUuid = msaJsonString(response, "id")
  msaPlayerName = msaJsonString(response, "name")

  If msaUuid = "" Or msaPlayerName = ""
    msaAccessToken = ""

    If msaHttpStatus = 404
      msaLastError = "This account does not own Minecraft: Java Edition."
    Else
      msaLastError = "Could not get the game profile (HTTP " + Str(msaHttpStatus) + ")."
    EndIf

    ProcedureReturn 0
  EndIf

  ProcedureReturn 1
EndProcedure

Procedure.i msaEnsureLogin()
  Protected.s clientId = msaClientId()
  Protected.s refreshToken = ReadPreferenceString("MsaRefreshToken", "")
  Protected.s response, accessToken, newRefreshToken

  msaLastError = ""

  If msaAccessToken <> ""
    ProcedureReturn 1
  EndIf

  If clientId = ""
    msaLastError = "No Azure client ID is configured (MsaClientId in vortex_launcher.conf)."
    ProcedureReturn 0
  EndIf

  If refreshToken = ""
    msaLastError = "Not logged in. Use the Microsoft login button in Settings."
    ProcedureReturn 0
  EndIf

  response = msaHttpRequest(#PB_HTTP_Post, #MsaTokenUrl, "grant_type=refresh_token&client_id=" + clientId + "&refresh_token=" + refreshToken + "&scope=" + URLEncoder(#MsaScope), "application/x-www-form-urlencoded")
  accessToken = msaJsonString(response, "access_token")

  If accessToken = ""
    msaLastError = "The Microsoft session has expired (" + msaJsonString(response, "error") + "). Log in again in Settings."
    ProcedureReturn 0
  EndIf

  newRefreshToken = msaJsonString(response, "refresh_token")

  If newRefreshToken <> ""
    WritePreferenceString("MsaRefreshToken", newRefreshToken)
  EndIf

  ProcedureReturn msaXboxChain(accessToken)
EndProcedure

Procedure.i msaLoginInteractive()
  Protected.s clientId = msaClientId()
  Protected.s response, deviceCode, userCode, verificationUri, oauthError, accessToken
  Protected.i loginWindow, codeGadget, openBrowserButton, cancelButton
  Protected.i event, interval, expiresIn, startTime, lastPoll, done, success

  msaLastError = ""

  If clientId = ""
    MessageRequester("Error", "No Azure client ID is configured!" + #CRLF$ + #CRLF$ + "Microsoft login requires a Mojang-approved Azure client ID." + #CRLF$ + "It can be set with the MsaClientId key in vortex_launcher.conf.")
    ProcedureReturn 0
  EndIf

  response = msaHttpRequest(#PB_HTTP_Post, #MsaDeviceCodeUrl, "client_id=" + clientId + "&scope=" + URLEncoder(#MsaScope), "application/x-www-form-urlencoded")

  deviceCode = msaJsonString(response, "device_code")
  userCode = msaJsonString(response, "user_code")
  verificationUri = msaJsonString(response, "verification_uri")
  interval = msaJsonInteger(response, "interval")
  expiresIn = msaJsonInteger(response, "expires_in")

  If deviceCode = ""
    MessageRequester("Error", "Could not start the Microsoft login (HTTP " + Str(msaHttpStatus) + ")." + #CRLF$ + #CRLF$ + "Check your internet connection and the configured client ID.")
    ProcedureReturn 0
  EndIf

  If interval < 1
    interval = 5
  EndIf

  If expiresIn < 1
    expiresIn = 900
  EndIf

  loginWindow = OpenWindow(#PB_Any, #PB_Ignore, #PB_Ignore, 320, 165, "Microsoft Login")

  If loginWindow
    TextGadget(#PB_Any, 5, 5, 310, 20, "1. Open " + verificationUri)
    TextGadget(#PB_Any, 5, 25, 310, 20, "2. Enter this code:")
    codeGadget = StringGadget(#PB_Any, 5, 45, 310, 25, userCode, #PB_String_ReadOnly)
    TextGadget(#PB_Any, 5, 75, 310, 20, "3. Confirm the login in the browser and wait")
    openBrowserButton = ButtonGadget(#PB_Any, 5, 100, 310, 27, "Copy code and open browser")
    cancelButton = ButtonGadget(#PB_Any, 5, 132, 310, 27, "Cancel")

    startTime = ElapsedMilliseconds()
    lastPoll = ElapsedMilliseconds()

    Repeat
      event = WindowEvent()

      If event = #PB_Event_Gadget
        Select EventGadget()
          Case openBrowserButton
            SetClipboardText(userCode)
            msaOpenBrowser(verificationUri)
          Case cancelButton
            done = 1
        EndSelect
      ElseIf event = #PB_Event_CloseWindow And EventWindow() = loginWindow
        done = 1
      ElseIf event = 0
        Delay(50)
      EndIf

      If Not done And ElapsedMilliseconds() - lastPoll >= interval * 1000
        lastPoll = ElapsedMilliseconds()

        response = msaHttpRequest(#PB_HTTP_Post, #MsaTokenUrl, "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=" + clientId + "&device_code=" + deviceCode, "application/x-www-form-urlencoded")

        accessToken = msaJsonString(response, "access_token")
        oauthError = msaJsonString(response, "error")

        If accessToken <> ""
          WritePreferenceString("MsaRefreshToken", msaJsonString(response, "refresh_token"))
          success = msaXboxChain(accessToken)
          done = 1
        ElseIf oauthError = "slow_down"
          interval + 5
        ElseIf oauthError <> "authorization_pending"
          msaLastError = "The login was not completed (" + oauthError + ")."
          done = 1
        EndIf
      EndIf

      If Not done And ElapsedMilliseconds() - startTime > expiresIn * 1000
        msaLastError = "The login timed out."
        done = 1
      EndIf
    Until done

    CloseWindow(loginWindow)
  EndIf

  If success
    WritePreferenceString("MsaPlayerName", msaPlayerName)
  ElseIf msaLastError <> ""
    MessageRequester("Error", "Microsoft login failed!" + #CRLF$ + #CRLF$ + msaLastError)
  EndIf

  ProcedureReturn success
EndProcedure

Procedure msaLogout()
  RemovePreferenceKey("MsaRefreshToken")
  RemovePreferenceKey("MsaPlayerName")

  msaAccessToken = ""
  msaPlayerName = ""
  msaUuid = ""
  msaXuid = ""
EndProcedure

Procedure.s msaStatusText()
  Protected.s savedName = ReadPreferenceString("MsaPlayerName", "")

  If ReadPreferenceString("MsaRefreshToken", "") <> ""
    If savedName <> ""
      ProcedureReturn "Account: " + savedName
    EndIf

    ProcedureReturn "Account: logged in"
  EndIf

  ProcedureReturn "Account: not logged in"
EndProcedure
