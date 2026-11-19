package com.example.passkey.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
/** 提供不依赖业务数据的服务健康检查接口。 */
public class HealthController {
    @GetMapping("/api/health")
    /** 返回服务已启动状态。 */
    public Map<String, String> health() { return Collections.singletonMap("status", "UP"); }
}
