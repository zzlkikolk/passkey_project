package com.example.passkey.service;

import com.example.passkey.config.PasskeyProperties;
import com.example.passkey.dto.LoginOptionsRequest;
import com.example.passkey.dto.LoginVerifyRequest;
import com.example.passkey.dto.RegisterOptionsRequest;
import com.example.passkey.dto.RegisterVerifyRequest;
import com.example.passkey.model.CredentialRecord;
import com.example.passkey.model.UserRecord;
import com.example.passkey.repository.CredentialRepository;
import com.example.passkey.repository.UserRepository;
import com.example.passkey.util.Base64Url;
import com.example.passkey.util.CborReader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class PasskeyService {
    private final ObjectMapper objectMapper;
    private final PasskeyProperties properties;
    private final UserRepository userRepository;
    private final CredentialRepository credentialRepository;
    private final ChallengeStore challengeStore;
    private final SecureRandom secureRandom = new SecureRandom();

    public PasskeyService(ObjectMapper objectMapper, PasskeyProperties properties, UserRepository userRepository,
                          CredentialRepository credentialRepository, ChallengeStore challengeStore) {
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.userRepository = userRepository;
        this.credentialRepository = credentialRepository;
        this.challengeStore = challengeStore;
    }

    public Map<String, Object> registerOptions(RegisterOptionsRequest request) {
        String username = normalize(request.username, "username");
        String displayName = request.displayName == null || request.displayName.trim().isEmpty() ? username : request.displayName.trim();
        UserRecord user = userRepository.findByUsername(username);
        if (user == null) user = userRepository.insert(username, displayName, Base64Url.encode(randomBytes(24)));
        String challenge = Base64Url.encode(randomBytes(32));
        challengeStore.save("register", username, challenge);

        Map<String, Object> rp = map("id", properties.getRpId(), "name", properties.getRpName());
        Map<String, Object> userJson = map("id", user.getUserHandle(), "name", user.getUsername(), "displayName", user.getDisplayName());
        Map<String, Object> selection = map("residentKey", "preferred", "userVerification", "preferred");
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("challenge", challenge);
        options.put("rp", rp);
        options.put("user", userJson);
        options.put("pubKeyCredParams", Collections.singletonList(map("type", "public-key", "alg", -7)));
        options.put("authenticatorSelection", selection);
        options.put("timeout", 60000);
        options.put("attestation", "none");
        return options;
    }

    @Transactional
    public Map<String, Object> verifyRegistration(RegisterVerifyRequest request) {
        String username = normalize(request.username, "username");
        String credentialId = normalize(request.credentialId, "credentialId");
        String expectedChallenge = challengeStore.consume("register", username);
        if (expectedChallenge == null) throw new IllegalArgumentException("注册挑战已过期，请重新开始");
        UserRecord user = userRepository.findByUsername(username);
        if (user == null) throw new IllegalArgumentException("用户不存在");
        try {
            JsonNode clientData = objectMapper.readTree(Base64Url.decode(request.clientDataJSON));
            verifyClientData(clientData, "webauthn.create", expectedChallenge);
            byte[] authData = readAttestationAuthData(Base64Url.decode(request.attestationObject));
            AuthenticatorData parsed = parseRegistrationAuthData(authData);
            verifyRpIdAndFlags(parsed.raw, true);
            if (!MessageDigest.isEqual(parsed.credentialId, Base64Url.decode(credentialId))) {
                throw new IllegalArgumentException("credentialId 与 attestationObject 不匹配");
            }
            if (credentialRepository.findByCredentialId(credentialId) != null) {
                throw new IllegalArgumentException("该 Passkey 已注册");
            }
            credentialRepository.insert(user.getId(), credentialId, Base64Url.encode(parsed.x), Base64Url.encode(parsed.y), parsed.signCount);
            return map("username", username, "credentialId", credentialId, "message", "Passkey 注册成功");
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("注册响应解析失败：" + e.getMessage(), e);
        }
    }

    public Map<String, Object> loginOptions(LoginOptionsRequest request) {
        String username = normalize(request.username, "username");
        UserRecord user = userRepository.findByUsername(username);
        if (user == null) throw new IllegalArgumentException("用户不存在，请先注册");
        List<Map<String, Object>> allowCredentials = new ArrayList<>();
        for (CredentialRecord credential : credentialRepository.findByUserId(user.getId())) {
            allowCredentials.add(map("type", "public-key", "id", credential.getCredentialId(), "transports", Arrays.asList("internal", "hybrid")));
        }
        if (allowCredentials.isEmpty()) throw new IllegalArgumentException("该用户还没有 Passkey");
        String challenge = Base64Url.encode(randomBytes(32));
        challengeStore.save("login", username, challenge);
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("challenge", challenge);
        options.put("rpId", properties.getRpId());
        options.put("allowCredentials", allowCredentials);
        options.put("userVerification", "preferred");
        options.put("timeout", 60000);
        return options;
    }

    @Transactional
    public Map<String, Object> verifyLogin(LoginVerifyRequest request) {
        String username = normalize(request.username, "username");
        String expectedChallenge = challengeStore.consume("login", username);
        if (expectedChallenge == null) throw new IllegalArgumentException("登录挑战已过期，请重新开始");
        CredentialRecord credential = credentialRepository.findByCredentialId(normalize(request.credentialId, "credentialId"));
        if (credential == null) throw new IllegalArgumentException("Passkey 不存在");
        UserRecord user = userRepository.findByUsername(username);
        if (user == null || user.getId() != credential.getUserId()) throw new IllegalArgumentException("Passkey 不属于当前用户");
        try {
            JsonNode clientData = objectMapper.readTree(Base64Url.decode(request.clientDataJSON));
            verifyClientData(clientData, "webauthn.get", expectedChallenge);
            byte[] authenticatorData = Base64Url.decode(request.authenticatorData);
            verifyRpIdAndFlags(authenticatorData, false);
            long newSignCount = readSignCount(authenticatorData);
            if (newSignCount != 0 && newSignCount <= credential.getSignCount()) throw new IllegalArgumentException("签名计数器异常，可能存在克隆凭据");
            byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(Base64Url.decode(request.clientDataJSON));
            byte[] signedData = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(createPublicKey(credential));
            signature.update(signedData);
            if (!signature.verify(normalizeEcdsaSignature(Base64Url.decode(request.signature)))) throw new IllegalArgumentException("Passkey 签名校验失败");
            if (newSignCount > credential.getSignCount()) credentialRepository.updateSignCount(credential.getId(), newSignCount);
            return map("username", username, "message", "Passkey 登录成功", "signCount", newSignCount);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("登录响应解析失败：" + e.getMessage(), e);
        }
    }

    private void verifyClientData(JsonNode clientData, String expectedType, String expectedChallenge) {
        if (!expectedType.equals(clientData.path("type").asText())) throw new IllegalArgumentException("clientData.type 不正确");
        if (!expectedChallenge.equals(clientData.path("challenge").asText())) throw new IllegalArgumentException("挑战值不匹配");
        if (!properties.getOrigin().equals(clientData.path("origin").asText())) throw new IllegalArgumentException("origin 不匹配");
    }

    private byte[] readAttestationAuthData(byte[] attestationObject) throws Exception {
        Object decoded = new CborReader(attestationObject).read();
        if (!(decoded instanceof Map)) throw new IllegalArgumentException("attestationObject 不是 CBOR map");
        Object authData = ((Map<?, ?>) decoded).get("authData");
        if (!(authData instanceof byte[])) throw new IllegalArgumentException("缺少 authData");
        return (byte[]) authData;
    }

    private AuthenticatorData parseRegistrationAuthData(byte[] authData) throws Exception {
        if (authData.length < 55) throw new IllegalArgumentException("authenticatorData 长度不足");
        int credentialLength = ((authData[53] & 0xff) << 8) | (authData[54] & 0xff);
        int credentialStart = 55;
        int keyStart = credentialStart + credentialLength;
        if (keyStart >= authData.length) throw new IllegalArgumentException("凭据公钥数据不完整");
        byte[] credentialId = Arrays.copyOfRange(authData, credentialStart, credentialStart + credentialLength);
        Object keyObject = new CborReader(Arrays.copyOfRange(authData, keyStart, authData.length)).read();
        if (!(keyObject instanceof Map)) throw new IllegalArgumentException("COSE 公钥格式不正确");
        Map<?, ?> cose = (Map<?, ?>) keyObject;
        long keyType = number(cose.get(1L));
        long algorithm = number(cose.get(3L));
        long curve = number(cose.get(-1L));
        if (keyType != 2 || algorithm != -7 || curve != 1) throw new IllegalArgumentException("仅支持 ES256 Passkey");
        byte[] x = bytes(cose.get(-2L));
        byte[] y = bytes(cose.get(-3L));
        return new AuthenticatorData(authData, credentialId, x, y, readSignCount(authData));
    }

    private void verifyRpIdAndFlags(byte[] authenticatorData, boolean registration) throws Exception {
        if (authenticatorData.length < 37) throw new IllegalArgumentException("authenticatorData 长度不足");
        byte[] rpHash = Arrays.copyOfRange(authenticatorData, 0, 32);
        byte[] expected = MessageDigest.getInstance("SHA-256").digest(properties.getRpId().getBytes(StandardCharsets.UTF_8));
        if (!MessageDigest.isEqual(rpHash, expected)) throw new IllegalArgumentException("rpIdHash 不匹配");
        int flags = authenticatorData[32] & 0xff;
        if ((flags & 0x01) == 0) throw new IllegalArgumentException("用户存在标志 UP 未设置");
        if (registration && (flags & 0x40) == 0) throw new IllegalArgumentException("注册响应缺少 attested credential data");
    }

    private long readSignCount(byte[] authData) {
        return ((long) (authData[33] & 0xff) << 24) | ((long) (authData[34] & 0xff) << 16)
                | ((long) (authData[35] & 0xff) << 8) | (authData[36] & 0xff);
    }

    private PublicKey createPublicKey(CredentialRecord credential) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECPublicKeySpec spec = new ECPublicKeySpec(new ECPoint(new BigInteger(1, Base64Url.decode(credential.getPublicKeyX())), new BigInteger(1, Base64Url.decode(credential.getPublicKeyY()))), parameters.getParameterSpec(java.security.spec.ECParameterSpec.class));
        return KeyFactory.getInstance("EC").generatePublic(spec);
    }

    private byte[] normalizeEcdsaSignature(byte[] signature) {
        if (signature.length > 0 && signature[0] == 0x30) return signature;
        if (signature.length != 64) return signature;
        byte[] r = trimInteger(Arrays.copyOfRange(signature, 0, 32));
        byte[] s = trimInteger(Arrays.copyOfRange(signature, 32, 64));
        byte[] body = new byte[4 + r.length + s.length];
        body[0] = 0x02; body[1] = (byte) r.length; System.arraycopy(r, 0, body, 2, r.length);
        int offset = 2 + r.length; body[offset] = 0x02; body[offset + 1] = (byte) s.length; System.arraycopy(s, 0, body, offset + 2, s.length);
        byte[] result = new byte[2 + body.length]; result[0] = 0x30; result[1] = (byte) body.length; System.arraycopy(body, 0, result, 2, body.length); return result;
    }

    private byte[] trimInteger(byte[] value) {
        int index = 0; while (index < value.length - 1 && value[index] == 0) index++;
        byte[] trimmed = Arrays.copyOfRange(value, index, value.length);
        if ((trimmed[0] & 0x80) != 0) { byte[] positive = new byte[trimmed.length + 1]; System.arraycopy(trimmed, 0, positive, 1, trimmed.length); return positive; }
        return trimmed;
    }

    private byte[] randomBytes(int length) { byte[] bytes = new byte[length]; secureRandom.nextBytes(bytes); return bytes; }
    private String normalize(String value, String field) { if (value == null || value.trim().isEmpty()) throw new IllegalArgumentException(field + " 不能为空"); return value.trim(); }
    private static long number(Object value) { if (!(value instanceof Number)) throw new IllegalArgumentException("COSE key 缺少数字字段"); return ((Number) value).longValue(); }
    private static byte[] bytes(Object value) { if (!(value instanceof byte[])) throw new IllegalArgumentException("COSE key 缺少二进制字段"); return (byte[]) value; }
    private static Map<String, Object> map(Object... values) { Map<String, Object> map = new LinkedHashMap<>(); for (int i = 0; i < values.length; i += 2) map.put(String.valueOf(values[i]), values[i + 1]); return map; }

    private static final class AuthenticatorData {
        private final byte[] raw;
        private final byte[] credentialId;
        private final byte[] x;
        private final byte[] y;
        private final long signCount;
        private AuthenticatorData(byte[] raw, byte[] credentialId, byte[] x, byte[] y, long signCount) { this.raw = raw; this.credentialId = credentialId; this.x = x; this.y = y; this.signCount = signCount; }
    }
}
