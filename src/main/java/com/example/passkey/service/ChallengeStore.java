package com.example.passkey.service;

import com.example.passkey.config.PasskeyProperties;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class ChallengeStore {
    private final StringRedisTemplate redis;
    private final PasskeyProperties properties;
    public ChallengeStore(StringRedisTemplate redis, PasskeyProperties properties) {
        this.redis = redis;
        this.properties = properties;
    }

    public void save(String type, String username, String challenge) {
        redis.opsForValue().set(key(type, username), challenge, properties.getChallengeTtlSeconds(), TimeUnit.SECONDS);
    }

    public String consume(String type, String username) {
        String key = key(type, username);
        String value = redis.opsForValue().get(key);
        if (value != null) redis.delete(key);
        return value;
    }

    private String key(String type, String username) { return "passkey:challenge:" + type + ":" + username; }
}
