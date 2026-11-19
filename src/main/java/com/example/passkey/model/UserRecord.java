package com.example.passkey.model;

public class UserRecord {
    private final long id;
    private final String username;
    private final String displayName;
    private final String userHandle;

    public UserRecord(long id, String username, String displayName, String userHandle) {
        this.id = id;
        this.username = username;
        this.displayName = displayName;
        this.userHandle = userHandle;
    }
    public long getId() { return id; }
    public String getUsername() { return username; }
    public String getDisplayName() { return displayName; }
    public String getUserHandle() { return userHandle; }
}
