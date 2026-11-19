package com.example.passkey.service;

import com.example.passkey.config.PasskeyProperties;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
/** 使用 Redis 保存一次性的注册和登录挑战值。 */
public class ChallengeStore {
    private final StringRedisTemplate redis;
    private final PasskeyProperties properties;
    /** 注入 Redis 客户端和挑战过期配置。 */
    public ChallengeStore(StringRedisTemplate redis, PasskeyProperties properties) {
        this.redis = redis;
        this.properties = properties;
    }

    /** 保存挑战并设置自动过期时间。 */
    public void save(String type, String username, String challenge) {
        // 挑战按认证类型和用户名隔离，避免注册和登录互相覆盖。
        redis.opsForValue().set(key(type, username), challenge, properties.getChallengeTtlSeconds(), TimeUnit.SECONDS);
    }

    /** 读取并删除挑战，保证一个挑战只能使用一次。 */
    public String consume(String type, String username) {
        String key = key(type, username);
        String value = redis.opsForValue().get(key);
        if (value != null) redis.delete(key); // 即使校验失败，也不允许重放同一个挑战。
        return value;
    }

    /** 生成 Redis key。 */
    private String key(String type, String username) { return "passkey:challenge:" + type + ":" + username; }
}
