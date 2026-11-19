package com.example.passkey;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
/** Passkey 示例应用启动入口。 */
public class PasskeyApplication {
    /** 启动 Spring Boot 内嵌 Web 服务。 */
    public static void main(String[] args) {
        SpringApplication.run(PasskeyApplication.class, args);
    }
}
