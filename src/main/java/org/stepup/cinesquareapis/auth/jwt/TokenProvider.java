package org.stepup.cinesquareapis.auth.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.stepup.cinesquareapis.auth.repository.UserRefreshTokenRepository;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

@PropertySource("classpath:jwt.yml")
@Service // JWT 생성 및 복호화
public class TokenProvider {
    private final String secretKey;
    private final String accessTokenExpirationTime;
    private final String refreshTokenExpirationTime;
    private final String issuer;

    private final UserRefreshTokenRepository userRefreshTokenRepository;

    public TokenProvider(
            @Value("${secret-key}") String secretKey,
            @Value("${access-token-expiration-time}") String accessTokenExpirationTime,
            @Value("${refresh-token-expiration-time}") String refreshTokenExpirationTime,
            @Value("${issuer}") String issuer,
            UserRefreshTokenRepository userRefreshTokenRepository
    ) {
        this.secretKey = secretKey;
        this.accessTokenExpirationTime = accessTokenExpirationTime;
        this.refreshTokenExpirationTime = refreshTokenExpirationTime;
        this.issuer = issuer;
        this.userRefreshTokenRepository = userRefreshTokenRepository;
    }

    // refresh token 만료 일시 조회
    public int getRefreshTokenExpirationTime() {
        return Integer.parseInt(refreshTokenExpirationTime);
    }

    // access token 생성
    public String createAccessToken(String userSpecification) {
        return Jwts.builder()
                .signWith(new SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS512.getJcaName()))   // HS512 알고리즘을 사용하여 secretKey를 이용해 서명
                .setSubject(userSpecification)  // JWT 토큰 제목
                .setIssuer(issuer)  // JWT 토큰 발급자
                .setIssuedAt(Timestamp.valueOf(LocalDateTime.now()))    // JWT 토큰 발급 시간
                .setExpiration(Date.from(Instant.now().plus(Long.parseLong(accessTokenExpirationTime), ChronoUnit.MINUTES)))    // JWT 토큰 만료 시간
                .compact(); // JWT 토큰 생성
    }

    // refresh token 생성
    // 리프레시 토큰은 사용자와 관련된 정보를 전혀 담지 않을 것이기 때문에 subject는 따로 설정하지 않음
    // 발급자와 발급시간, 만료시간만 설정
    public String createRefreshToken() {
        return Jwts.builder()
                .signWith(new SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS512.getJcaName()))
                .setIssuer(issuer)
                .setIssuedAt(Timestamp.valueOf(LocalDateTime.now()))
                .setExpiration(Date.from(Instant.now().plus(Long.parseLong(refreshTokenExpirationTime), ChronoUnit.MINUTES)))
                .compact();
    }

    // Subject에는 SignService의 singIn()에서 토큰을 생성할 때 인자로 넘긴 "{회원ID}:{회원타입}" 이 있음
    public String validateTokenAndGetSubject(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey.getBytes())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    @Transactional
    public String recreateAccessToken(String oldAccessToken) throws JsonProcessingException {
        String subject = decodeJwtPayloadSubject(oldAccessToken);

        Integer userId = Integer.parseInt(subject.split(":")[0]);

        userRefreshTokenRepository.findById(userId)
                .ifPresentOrElse(
                        userRefreshToken -> {
                            userRefreshTokenRepository.save(userRefreshToken);
                        },
                        () -> { throw new ExpiredJwtException(null, null, "Refresh token expired."); }
                );

        return createAccessToken(subject);
    }

    @Transactional(readOnly = true)
    public void validateRefreshToken(String oldAccessToken, String refreshToken) throws JsonProcessingException {
        Jws<Claims> claimsJws;
        try {
            claimsJws = validateAndParseToken(refreshToken);
        } catch (JwtException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid refresh token", e);
        }

        Integer userId = Integer.parseInt(decodeJwtPayloadSubject(oldAccessToken).split(":")[0]);

        userRefreshTokenRepository.findById(userId)
                .filter(userRefreshToken -> {
                    // 만료 시간 체크
                    Date expiration = claimsJws.getBody().getExpiration();
                    if (expiration.before(new Date())) {
                        throw new ExpiredJwtException(null, null, "Refresh token expired.");
                    }
                    return userRefreshToken.validateRefreshToken(refreshToken);
                })
                .orElseThrow(() -> new ExpiredJwtException(null, null, "Refresh token expired."));
    }

    // validateAndParseToken
    private Jws<Claims> validateAndParseToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey.getBytes())
                    .build()
                    .parseClaimsJws(token);
        } catch (JwtException e) {
            System.err.println("JWT validation failed: " + e.getMessage());
            throw e;
        }
    }

    private String decodeJwtPayloadSubject(String oldAccessToken) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();

        return objectMapper.readValue(
                new String(Base64.getDecoder().decode(oldAccessToken.split("\\.")[1]), StandardCharsets.UTF_8),
                Map.class
        ).get("sub").toString();
    }

    // Bearer 토큰 파싱 메서드
    // HTTP 요청의 헤더에서 headerName(Authorization) 으로 값을 찾아서
    // Bearer로 시작하는지 확인 후
    // 접두어를 제외한 토큰값으로 파싱
    // 그 외에는 null을 반환
    public String parseBearerToken(HttpServletRequest request, String headerName) {
        return Optional.ofNullable(request.getHeader(headerName))
                .filter(token -> token.length() > 7 && token.substring(0, 7).equalsIgnoreCase("Bearer "))
                .map(token -> token.substring(7))
                .orElse(null);
    }

    // 로그인 정보 객체 반환 메서드
    // 파싱된 토큰이 null이 아니면서 길이가 너무 짧지 않을 때
    // 토큰을 복호화하여
    // userId와 RoleType을 토대로 스프링 시큐리티에서 사용하는 User 객체를 반환
    // 그 외에는 익명 객체를 생성
    public User getUserFromAccessToken(String token) {
        String[] split = Optional.ofNullable(token)
                .filter(subject -> subject.length() >= 10)
                .map(t -> validateTokenAndGetSubject(t))
                .orElse("anonymous:anonymous")
                .split(":");

        return new User(split[0], "", List.of(new SimpleGrantedAuthority(split[1])));
    }
}