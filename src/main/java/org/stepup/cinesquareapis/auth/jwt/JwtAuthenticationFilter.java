package org.stepup.cinesquareapis.auth.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.stepup.cinesquareapis.auth.repository.UserRefreshTokenRepository;
import org.stepup.cinesquareapis.user.repository.UserRepository;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

// JWT를 통해 권한을 부여하는 필터

@Order(0)
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final TokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final UserRefreshTokenRepository userRefreshTokenRepository;

    // 인증 정보를 설정
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            // 1. AccessToken 추출
            String accessToken = parseBearerToken(request, HttpHeaders.AUTHORIZATION);

            // 2. 로그인 정보 객체(spring security 지원 user) or 익명 객체 반환
            User user = parseUserSpecification(accessToken);

            // 3. 스프링 시큐리티에서 사용할 UsernamePasswordAuthenticationToken 객체를 생성
            AbstractAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(user, accessToken, user.getAuthorities());
            authenticated.setDetails(new WebAuthenticationDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authenticated);
        } catch (ExpiredJwtException e) {
            // Jwt 토큰이 만료된 경우, RefreshToken이 유효하다면 AccessToken 재생성
            reissueAccessToken(request, response, e);
        } catch (Exception e) {
            request.setAttribute("exception", e);
        }

        filterChain.doFilter(request, response);
    }

    // AccessToken 재발급
    private void reissueAccessToken(HttpServletRequest request, HttpServletResponse response, Exception exception) {
        try {
            // 1. RefreshToken, 만료된 AccessToken 추출
            String refreshToken = parseBearerToken(request, "Refresh-Token");
            if (refreshToken == null) {
                throw exception;
            }
            String oldAccessToken = parseBearerToken(request, HttpHeaders.AUTHORIZATION);

            // 2. 토큰 검증
            tokenProvider.validateRefreshToken(refreshToken, oldAccessToken);

            // 3. AccessToken 재발급
            String newAccessToken = tokenProvider.recreateAccessToken(oldAccessToken);
            User user = parseUserSpecification(newAccessToken);
            AbstractAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(user, newAccessToken, user.getAuthorities());
            authenticated.setDetails(new WebAuthenticationDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authenticated);

            response.setHeader("New-Access-Token", newAccessToken);
        } catch (Exception e) {
            request.setAttribute("exception", e);
        }
    }

    // Bearer 토큰 파싱 메서드
    private String parseBearerToken(HttpServletRequest request, String headerName) {
        return Optional.ofNullable(request.getHeader(headerName))
                .filter(token -> token.length() > 7 && token.substring(0, 7).equalsIgnoreCase("Bearer "))
                .map(token -> token.substring(7))
                .orElse(null);
    }

    // 로그인 정보 객체 반환 메서드
    private User parseUserSpecification(String token) {
        String[] split = Optional.ofNullable(token)
                .filter(subject -> subject.length() >= 10)
                .map(tokenProvider::validateTokenAndGetSubject)
                .orElse("anonymous:anonymous")
                .split(":");

        return new User(split[0], "", List.of(new SimpleGrantedAuthority(split[1])));
    }
}