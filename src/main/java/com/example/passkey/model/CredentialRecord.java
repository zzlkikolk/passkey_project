package com.example.passkey.model;

public class CredentialRecord {
    private final long id;
    private final long userId;
    private final String credentialId;
    private final String publicKeyX;
    private final String publicKeyY;
    private final long signCount;

    public CredentialRecord(long id, long userId, String credentialId, String publicKeyX, String publicKeyY, long signCount) {
        this.id = id;
        this.userId = userId;
        this.credentialId = credentialId;
        this.publicKeyX = publicKeyX;
        this.publicKeyY = publicKeyY;
        this.signCount = signCount;
    }
    public long getId() { return id; }
    public long getUserId() { return userId; }
    public String getCredentialId() { return credentialId; }
    public String getPublicKeyX() { return publicKeyX; }
    public String getPublicKeyY() { return publicKeyY; }
    public long getSignCount() { return signCount; }
}
