package com.example.sso.appa.infrastructure.adapter.out.security;

import com.example.sso.appa.application.port.out.AuthenticationPort;
import com.example.sso.appa.domain.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class KeycloakAuthenticationAdapter implements AuthenticationPort {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAuthenticationAdapter.class);
    private final JwtDecoder jwtDecoder;

    public KeycloakAuthenticationAdapter(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public User extractUserFromToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return new User(
                    jwt.getClaimAsString("sub"),
                    jwt.getClaimAsString("preferred_username"),
                    jwt.getClaimAsString("email"),
                    jwt.getClaimAsString("given_name"),
                    jwt.getClaimAsString("family_name"),
                    extractRoles(jwt)
            );
        } catch (Exception e) {
            log.error("Error extracting user from token", e);
            throw new RuntimeException("Failed to extract user from token", e);
        }
    }

    @Override
    public boolean validateToken(String token) {
        try {
            jwtDecoder.decode(token);
            return true;
        } catch (Exception e) {
            log.error("Token validation failed", e);
            return false;
        }
    }

    private List<String> extractRoles(Jwt jwt) {
        var realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            return (List<String>) realmAccess.get("roles");
        }
        return List.of();
    }
}
