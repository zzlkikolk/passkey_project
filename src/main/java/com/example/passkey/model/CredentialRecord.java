package com.example.passkey.model;

/** Passkey 凭据表的只读领域对象。 */
public class CredentialRecord {
    private final long id;
    private final long userId;
    private final String credentialId;
    private final String publicKeyX;
    private final String publicKeyY;
    private final long signCount;

    /** 使用数据库查询结果创建凭据对象。 */
    public CredentialRecord(long id, long userId, String credentialId, String publicKeyX, String publicKeyY, long signCount) {
        this.id = id;
        this.userId = userId;
        this.credentialId = credentialId;
        this.publicKeyX = publicKeyX;
        this.publicKeyY = publicKeyY;
        this.signCount = signCount;
    }
    /** 返回数据库主键。 */
    public long getId() { return id; }
    /** 返回归属用户主键。 */
    public long getUserId() { return userId; }
    /** 返回 WebAuthn credential ID。 */
    public String getCredentialId() { return credentialId; }
    /** 返回 ES256 公钥 X 坐标。 */
    public String getPublicKeyX() { return publicKeyX; }
    /** 返回 ES256 公钥 Y 坐标。 */
    public String getPublicKeyY() { return publicKeyY; }
    /** 返回最近一次认证器签名计数。 */
    public long getSignCount() { return signCount; }
}
