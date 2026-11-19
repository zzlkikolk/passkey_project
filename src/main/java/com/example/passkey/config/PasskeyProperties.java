package com.example.passkey.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "passkey")
/** 读取 WebAuthn 依赖的 RP、Origin 和挑战过期时间配置。 */
public class PasskeyProperties {
    /** WebAuthn Relying Party ID，通常使用当前站点域名。 */
    private String rpId;
    /** 在设备注册界面展示的站点名称。 */
    private String rpName;
    /** 浏览器 clientDataJSON 中必须匹配的 Origin。 */
    private String origin;
    /** Redis 中挑战值的有效期，单位为秒。 */
    private long challengeTtlSeconds = 300;

    /** 返回 RP ID。 */
    public String getRpId() { return rpId; }
    /** 设置 RP ID。 */
    public void setRpId(String rpId) { this.rpId = rpId; }
    /** 返回 RP 展示名称。 */
    public String getRpName() { return rpName; }
    /** 设置 RP 展示名称。 */
    public void setRpName(String rpName) { this.rpName = rpName; }
    /** 返回允许的请求来源。 */
    public String getOrigin() { return origin; }
    /** 设置允许的请求来源。 */
    public void setOrigin(String origin) { this.origin = origin; }
    /** 返回挑战有效期。 */
    public long getChallengeTtlSeconds() { return challengeTtlSeconds; }
    /** 设置挑战有效期。 */
    public void setChallengeTtlSeconds(long challengeTtlSeconds) { this.challengeTtlSeconds = challengeTtlSeconds; }
}
