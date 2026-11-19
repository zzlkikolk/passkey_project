package com.example.passkey.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginVerifyRequest {
    public String username;
    public String credentialId;
    public String clientDataJSON;
    public String authenticatorData;
    public String signature;
}
