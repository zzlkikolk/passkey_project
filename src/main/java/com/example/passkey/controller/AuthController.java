package com.example.passkey.controller;

import com.example.passkey.dto.LoginOptionsRequest;
import com.example.passkey.dto.LoginVerifyRequest;
import com.example.passkey.dto.RegisterOptionsRequest;
import com.example.passkey.dto.RegisterVerifyRequest;
import com.example.passkey.service.PasskeyService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
/** 暴露 Passkey 注册和登录的四个 HTTP 接口。 */
public class AuthController {
    private final PasskeyService passkeyService;
    /** 注入认证领域服务。 */
    public AuthController(PasskeyService passkeyService) { this.passkeyService = passkeyService; }

    @PostMapping("/register/options")
    /** 创建浏览器注册 Passkey 所需的 PublicKeyCredentialCreationOptions。 */
    public ResponseEntity<Map<String, Object>> registerOptions(@Valid @RequestBody RegisterOptionsRequest request) {
        return ResponseEntity.ok(passkeyService.registerOptions(request));
    }

    @PostMapping("/register/verify")
    /** 校验浏览器返回的注册凭据并保存公钥。 */
    public ResponseEntity<Map<String, Object>> registerVerify(@Valid @RequestBody RegisterVerifyRequest request) {
        return ResponseEntity.ok(passkeyService.verifyRegistration(request));
    }

    @PostMapping("/login/options")
    /** 创建浏览器发起 Passkey 登录所需的请求参数。 */
    public ResponseEntity<Map<String, Object>> loginOptions(@Valid @RequestBody LoginOptionsRequest request) {
        return ResponseEntity.ok(passkeyService.loginOptions(request));
    }

    @PostMapping("/login/verify")
    /** 校验登录签名、RP ID 和签名计数器。 */
    public ResponseEntity<Map<String, Object>> loginVerify(@Valid @RequestBody LoginVerifyRequest request) {
        return ResponseEntity.ok(passkeyService.verifyLogin(request));
    }
}
