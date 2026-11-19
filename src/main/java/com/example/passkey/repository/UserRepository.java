package com.example.passkey.repository;

import com.example.passkey.model.UserRecord;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Repository;

import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.List;

@Repository
/** 使用 JdbcTemplate 访问 passkey_user 表。 */
public class UserRepository {
    private final JdbcTemplate jdbc;
    /** 保存数据库访问模板。 */
    public UserRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    /** 按登录用户名查询用户，不存在时返回 null。 */
    public UserRecord findByUsername(String username) {
        List<UserRecord> users = jdbc.query("SELECT id, username, display_name, user_handle FROM passkey_user WHERE username = ?",
                (rs, row) -> new UserRecord(rs.getLong("id"), rs.getString("username"), rs.getString("display_name"), rs.getString("user_handle")), username);
        return users.isEmpty() ? null : users.get(0);
    }

    /** 按数据库主键查询用户，不存在时返回 null。 */
    public UserRecord findById(long id) {
        List<UserRecord> users = jdbc.query("SELECT id, username, display_name, user_handle FROM passkey_user WHERE id = ?",
                (rs, row) -> new UserRecord(rs.getLong("id"), rs.getString("username"), rs.getString("display_name"), rs.getString("user_handle")), id);
        return users.isEmpty() ? null : users.get(0);
    }

    /** 创建用户并返回数据库生成的主键。 */
    public UserRecord insert(String username, String displayName, String userHandle) {
        // 使用 GeneratedKeyHolder 获取 AUTO_INCREMENT 生成的用户 ID。
        KeyHolder keyHolder = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            PreparedStatement statement = connection.prepareStatement(
                    "INSERT INTO passkey_user(username, display_name, user_handle) VALUES (?, ?, ?)", Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, username);
            statement.setString(2, displayName);
            statement.setString(3, userHandle);
            return statement;
        }, keyHolder);
        return new UserRecord(keyHolder.getKey().longValue(), username, displayName, userHandle);
    }
}
