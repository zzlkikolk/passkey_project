package com.example.passkey.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "passkey")
public class PasskeyProperties {
    private String rpId;
    private String rpName;
    private String origin;
    private long challengeTtlSeconds = 300;

    public String getRpId() { return rpId; }
    public void setRpId(String rpId) { this.rpId = rpId; }
    public String getRpName() { return rpName; }
    public void setRpName(String rpName) { this.rpName = rpName; }
    public String getOrigin() { return origin; }
    public void setOrigin(String origin) { this.origin = origin; }
    public long getChallengeTtlSeconds() { return challengeTtlSeconds; }
    public void setChallengeTtlSeconds(long challengeTtlSeconds) { this.challengeTtlSeconds = challengeTtlSeconds; }
}
