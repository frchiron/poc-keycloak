package com.example.sso.appc.infrastructure.adapter.in.web;

import com.example.sso.appc.application.port.in.GetUserInfoUseCase;
import com.example.sso.appc.domain.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:3003")
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    private final GetUserInfoUseCase getUserInfoUseCase;

    public UserController(GetUserInfoUseCase getUserInfoUseCase) {
        this.getUserInfoUseCase = getUserInfoUseCase;
    }

    @GetMapping("/user")
    public ResponseEntity<User> getUserInfo(@AuthenticationPrincipal Jwt jwt) {
        log.info("Getting user info from token");
        User user = getUserInfoUseCase.getUserInfo(jwt.getTokenValue());
        return ResponseEntity.ok(user);
    }

    @GetMapping("/app-info")
    public ResponseEntity<Map<String, String>> getAppInfo(@AuthenticationPrincipal Jwt jwt) {
        log.info("Getting app info for App C");
        Map<String, String> info = new HashMap<>();
        info.put("appName", "Application C");
        info.put("appId", "app-c");
        info.put("description", "This is Application C - Supply Chain Management");
        info.put("username", jwt.getClaimAsString("preferred_username"));
        info.put("redirectToAppA", "http://localhost:3001");
        info.put("redirectToAppB", "http://localhost:3002");
        return ResponseEntity.ok(info);
    }

    @GetMapping("/protected")
    public ResponseEntity<Map<String, String>> protectedEndpoint(@AuthenticationPrincipal Jwt jwt) {
        log.info("Accessing protected endpoint in App C");
        Map<String, String> response = new HashMap<>();
        response.put("message", "This is a protected resource in App C");
        response.put("user", jwt.getClaimAsString("preferred_username"));
        response.put("email", jwt.getClaimAsString("email"));
        return ResponseEntity.ok(response);
    }
}
