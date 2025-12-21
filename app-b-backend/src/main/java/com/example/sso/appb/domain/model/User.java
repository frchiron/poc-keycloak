package com.example.sso.appb.domain.model;

import java.util.List;

public record User(
    String id,
    String username,
    String email,
    String firstName,
    String lastName,
    List<String> roles
) {}
