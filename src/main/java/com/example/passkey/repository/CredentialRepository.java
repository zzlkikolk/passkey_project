package com.example.passkey.repository;

import com.example.passkey.model.CredentialRecord;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class CredentialRepository {
    private final JdbcTemplate jdbc;
    public CredentialRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public CredentialRecord findByCredentialId(String credentialId) {
        List<CredentialRecord> records = jdbc.query("SELECT id, user_id, credential_id, public_key_x, public_key_y, sign_count FROM passkey_credential WHERE credential_id = ?",
                (rs, row) -> new CredentialRecord(rs.getLong("id"), rs.getLong("user_id"), rs.getString("credential_id"), rs.getString("public_key_x"), rs.getString("public_key_y"), rs.getLong("sign_count")), credentialId);
        return records.isEmpty() ? null : records.get(0);
    }

    public List<CredentialRecord> findByUserId(long userId) {
        return jdbc.query("SELECT id, user_id, credential_id, public_key_x, public_key_y, sign_count FROM passkey_credential WHERE user_id = ? ORDER BY id",
                (rs, row) -> new CredentialRecord(rs.getLong("id"), rs.getLong("user_id"), rs.getString("credential_id"), rs.getString("public_key_x"), rs.getString("public_key_y"), rs.getLong("sign_count")), userId);
    }

    public void insert(long userId, String credentialId, String publicKeyX, String publicKeyY, long signCount) {
        jdbc.update("INSERT INTO passkey_credential(user_id, credential_id, public_key_x, public_key_y, sign_count) VALUES (?, ?, ?, ?, ?)",
                userId, credentialId, publicKeyX, publicKeyY, signCount);
    }

    public void updateSignCount(long id, long signCount) {
        jdbc.update("UPDATE passkey_credential SET sign_count = ? WHERE id = ?", signCount, id);
    }
}
