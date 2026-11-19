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
public class UserRepository {
    private final JdbcTemplate jdbc;
    public UserRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public UserRecord findByUsername(String username) {
        List<UserRecord> users = jdbc.query("SELECT id, username, display_name, user_handle FROM passkey_user WHERE username = ?",
                (rs, row) -> new UserRecord(rs.getLong("id"), rs.getString("username"), rs.getString("display_name"), rs.getString("user_handle")), username);
        return users.isEmpty() ? null : users.get(0);
    }

    public UserRecord findById(long id) {
        List<UserRecord> users = jdbc.query("SELECT id, username, display_name, user_handle FROM passkey_user WHERE id = ?",
                (rs, row) -> new UserRecord(rs.getLong("id"), rs.getString("username"), rs.getString("display_name"), rs.getString("user_handle")), id);
        return users.isEmpty() ? null : users.get(0);
    }

    public UserRecord insert(String username, String displayName, String userHandle) {
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
