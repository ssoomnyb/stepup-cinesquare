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
import org.stepup.cinesquareapis.auth.entity.UserRefreshToken;
import org.stepup.cinesquareapis.auth.repository.UserRefreshTokenRepository;
import org.stepup.cinesquareapis.common.exception.enums.CommonErrorCode;
import org.stepup.cinesquareapis.common.exception.enums.CustomErrorCode;
import org.stepup.cinesquareapis.common.exception.exception.RestApiException;
import org.stepup.cinesquareapis.user.repository.UserRepository;
import org.stepup.cinesquareapis.util.CookieUtil;

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
        // 특정 경로에 대해 필터를 건너뛰기
        if (shouldNotFilter(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 1. 엑세스 토큰 추출
        String accessToken = parseBearerToken(request, HttpHeaders.AUTHORIZATION);

        try {
            // 2. 로그인 정보 객체(spring security 지원 user) or 익명 객체 반환
            User user = getUserFromAccessToken(accessToken);

            // 3. 스프링 시큐리티에서 사용할 UsernamePasswordAuthenticationToken 객체를 생성
            AbstractAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(user, accessToken, user.getAuthorities());
            authenticated.setDetails(new WebAuthenticationDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authenticated);
        } catch (ExpiredJwtException e) {
            // 4. Jwt 토큰이 만료됨, Refresh Token이 유효하다면 Access Token 재생성
            try {
                // Refresh Token 추출
                String refreshToken = extractRefreshToken(request);

                // Refresh 토큰 검증
                tokenProvider.validateRefreshToken(accessToken, refreshToken);

                // Access Token, Refresh-Token 재발급
                reissueAccessAndRefreshToken(request, response, accessToken);
            } catch (RestApiException re) {
                throw new RestApiException(CommonErrorCode.UNAUTHORIZED);
            }
        } catch (RestApiException e) {
            throw new RestApiException(CommonErrorCode.UNAUTHORIZED);
        } catch (Exception e) {
            request.setAttribute("exception", e);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
            return;
        }

        filterChain.doFilter(request, response);
    }

    // 특정 요청에 대해 필터를 건너뛸지 결정하는 메서드
    public boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return "/api/auth/reissue-access-token".equals(path);
    }

    // Bearer 토큰 파싱 메서드
    private String parseBearerToken(HttpServletRequest request, String headerName) {
        return Optional.ofNullable(request.getHeader(headerName))
                .filter(token -> token.length() > 7 && token.substring(0, 7).equalsIgnoreCase("Bearer "))
                .map(token -> token.substring(7))
                .orElse(null);
    }

    // 로그인 정보 객체 반환 메서드
    private User getUserFromAccessToken(String token) {
        String[] split = Optional.ofNullable(token)
                .filter(subject -> subject.length() >= 10)
                .map(tokenProvider::validateTokenAndGetSubject)
                .orElse("anonymous:anonymous")
                .split(":");

        return new User(split[0], "", List.of(new SimpleGrantedAuthority(split[1])));
    }

    // 사용자 인증 처리 메서드
    private void authenticateUser(HttpServletRequest request, String accessToken, User user) {
        AbstractAuthenticationToken authenticationToken = UsernamePasswordAuthenticationToken.authenticated(user, accessToken, user.getAuthorities());
        authenticationToken.setDetails(new WebAuthenticationDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }

    // Refresh Token을 추출하는 메서드 (헤더 우선, 없으면 쿠키에서 추출)
    private String extractRefreshToken(HttpServletRequest request) {
        String refreshToken = request.getHeader("Refresh-Token");
        if (refreshToken == null) {
            refreshToken = CookieUtil.getCookieValue(request, "Refresh-Token");
        }
        if (refreshToken == null) {
            throw new RestApiException(CustomErrorCode.EXPIRED_ACCESS_TOKEN);
        }
        return refreshToken;
    }

    // Access Token, Refresh-Token 재발급
    private void reissueAccessAndRefreshToken(HttpServletRequest request, HttpServletResponse response, String oldAccessToken) throws IOException {
        try {
            // 새 Access Token 발급
            String newAccessToken = tokenProvider.recreateAccessToken(oldAccessToken);

            // 로그인 정보 객체
            User securityUser = getUserFromAccessToken(newAccessToken);

            authenticateUser(request, newAccessToken, securityUser);
            response.setHeader("New-Access-Token", newAccessToken);

            // 새 Refresh Token 발급 및 쿠키 설정
            String newRefreshToken = tokenProvider.createRefreshToken();
            CookieUtil.addCookie(response, "Refresh-Token", newRefreshToken, 10);

            // 새로운 Refresh Token을 DB에 저장
            Integer userId = Integer.parseInt(securityUser.getUsername());
            org.stepup.cinesquareapis.user.entity.User cineUser = userRepository.findById(userId)
                    .orElseThrow(() -> new RestApiException(CustomErrorCode.NOT_FOUND_USER));

            UserRefreshToken newUserRefreshToken = new UserRefreshToken(cineUser, newRefreshToken, 10);
            userRefreshTokenRepository.save(newUserRefreshToken);
        } catch (RestApiException ex) {
            request.setAttribute("exception", ex);
            response.sendError(ex.getErrorCode().getHttpStatus().value(), ex.getErrorCode().getMessage());
        } catch (Exception ex) {
            request.setAttribute("exception", ex);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token has expired and reissue failed");
        }
    }
}