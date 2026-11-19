package com.example.passkey.model;

/** 用户表的只读领域对象。 */
public class UserRecord {
    private final long id;
    private final String username;
    private final String displayName;
    private final String userHandle;

    /** 使用数据库查询结果创建用户对象。 */
    public UserRecord(long id, String username, String displayName, String userHandle) {
        this.id = id;
        this.username = username;
        this.displayName = displayName;
        this.userHandle = userHandle;
    }
    /** 返回数据库主键。 */
    public long getId() { return id; }
    /** 返回登录用户名。 */
    public String getUsername() { return username; }
    /** 返回显示名称。 */
    public String getDisplayName() { return displayName; }
    /** 返回 WebAuthn user.id。 */
    public String getUserHandle() { return userHandle; }
}
