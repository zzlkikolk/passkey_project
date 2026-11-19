package com.example.passkey.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
/** 接收创建注册挑战所需的用户基本信息。 */
public class RegisterOptionsRequest {
    /** 用户登录名。 */
    public String username;
    /** 用户在设备注册界面展示的名称。 */
    public String displayName;
}
