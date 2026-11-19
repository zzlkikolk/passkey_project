package com.example.passkey.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
/** 接收创建登录挑战所需的用户名。 */
public class LoginOptionsRequest {
    /** 要登录的用户名。 */
    public String username;
}
