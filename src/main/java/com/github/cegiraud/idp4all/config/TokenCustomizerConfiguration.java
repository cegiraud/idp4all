package com.github.cegiraud.idp4all.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Collections;

@Configuration
public class TokenCustomizerConfiguration {

    public static final String ROLES = "roles";

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return (context) -> {
            String tokenType = context.getTokenType().getValue();
            if (OidcParameterNames.ID_TOKEN.equals(tokenType) || OAuth2TokenType.ACCESS_TOKEN.getValue().equals(tokenType)) {
                OidcUser oidcUser = (OidcUser) context.getPrincipal().getPrincipal();

                context.getClaims().claim(StandardClaimNames.EMAIL, oidcUser.getEmail());
                context.getClaims().claim(StandardClaimNames.NAME, oidcUser.getFullName());
                context.getClaims().claim(StandardClaimNames.FAMILY_NAME, oidcUser.getFamilyName());
                context.getClaims().claim(StandardClaimNames.GIVEN_NAME, oidcUser.getGivenName());
                context.getClaims().claim(StandardClaimNames.PREFERRED_USERNAME, oidcUser.getEmail());
                context.getClaims().claim(ROLES, oidcUser.hasClaim(ROLES) ? oidcUser.getClaimAsStringList(ROLES) : Collections.emptyList());
            }
        };
    }
}