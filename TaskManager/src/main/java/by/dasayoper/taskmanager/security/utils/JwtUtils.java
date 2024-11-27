package by.dasayoper.taskmanager.security.utils;

import by.dasayoper.taskmanager.repository.BlacklistRepository;
import by.dasayoper.taskmanager.security.details.AccountUserDetails;
import by.dasayoper.taskmanager.security.details.AccountUserDetailsService;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;


@Component
@RequiredArgsConstructor
public class JwtUtils {
    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.access.expiration}")
    private long accessTokenExpiration;
    @Value("${jwt.refresh.expiration}")
    private long refreshTokenExpiration;

    private static final String AUTHORIZATION_HEADER_NAME = "AUTHORIZATION";
    private static final String BEARER = "Bearer ";

    private final AccountUserDetailsService accountUserDetailsService;
    private final BlacklistRepository blacklistRepository;

    public String createAccessToken(AccountUserDetails userDetails) {
        return createToken(userDetails, accessTokenExpiration);
    }

    public String createRefreshToken(AccountUserDetails userDetails) {
        return createToken(userDetails, refreshTokenExpiration);
    }

    public String createAccessTokenFromRefreshToken(String refreshToken) {
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC256(secret)).build().verify(refreshToken);
        String email = decodedJWT.getSubject();
        AccountUserDetails userDetails = (AccountUserDetails) accountUserDetailsService.loadUserByUsername(email);
        return createAccessToken(userDetails);
    }

    private String createToken(AccountUserDetails userDetails, long expirationTime) {
        return JWT.create()
                .withSubject(userDetails.getUsername())
                .withClaim("role", userDetails.getAccount().getRole().toString())
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + expirationTime))
                .sign(Algorithm.HMAC256(secret));
    }

    public boolean validateToken(String token) {
        try {
            JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
            return true;
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    public String extractToken(HttpServletRequest request) {
        String header = request.getHeader(AUTHORIZATION_HEADER_NAME);
        if (header != null && header.startsWith(BEARER)) {
            return header.substring(7);
        }
        return null;
    }

    public Authentication getAuthentication(String token) {
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
        String email = decodedJWT.getSubject();
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(decodedJWT.getClaim("role").asString()));
        return new UsernamePasswordAuthenticationToken(accountUserDetailsService.loadUserByUsername(email), null, authorities);
    }

    public boolean isTokenBlacklisted(String token) {
        return blacklistRepository.exists(token);
    }

    public void blacklistToken(String token) {
        blacklistRepository.save(token);
    }
}
