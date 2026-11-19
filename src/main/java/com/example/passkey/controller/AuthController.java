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
public class AuthController {
    private final PasskeyService passkeyService;
    public AuthController(PasskeyService passkeyService) { this.passkeyService = passkeyService; }

    @PostMapping("/register/options")
    public ResponseEntity<Map<String, Object>> registerOptions(@Valid @RequestBody RegisterOptionsRequest request) {
        return ResponseEntity.ok(passkeyService.registerOptions(request));
    }

    @PostMapping("/register/verify")
    public ResponseEntity<Map<String, Object>> registerVerify(@Valid @RequestBody RegisterVerifyRequest request) {
        return ResponseEntity.ok(passkeyService.verifyRegistration(request));
    }

    @PostMapping("/login/options")
    public ResponseEntity<Map<String, Object>> loginOptions(@Valid @RequestBody LoginOptionsRequest request) {
        return ResponseEntity.ok(passkeyService.loginOptions(request));
    }

    @PostMapping("/login/verify")
    public ResponseEntity<Map<String, Object>> loginVerify(@Valid @RequestBody LoginVerifyRequest request) {
        return ResponseEntity.ok(passkeyService.verifyLogin(request));
    }
}
