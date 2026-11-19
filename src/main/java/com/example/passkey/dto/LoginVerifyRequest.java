package com.example.passkey.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
/** 接收浏览器返回的 WebAuthn 登录断言。 */
public class LoginVerifyRequest {
    /** 发起登录挑战时使用的用户名。 */
    public String username;
    /** 浏览器凭据的 rawId，使用 Base64URL 编码。 */
    public String credentialId;
    /** 浏览器生成的 clientDataJSON，使用 Base64URL 编码。 */
    public String clientDataJSON;
    /** 认证器数据，使用 Base64URL 编码。 */
    public String authenticatorData;
    /** 认证器签名，使用 Base64URL 编码。 */
    public String signature;
}
