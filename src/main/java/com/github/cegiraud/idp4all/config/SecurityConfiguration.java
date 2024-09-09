package com.github.cegiraud.idp4all.config;

import com.github.cegiraud.idp4all.properties.JwtSignatureProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OidcUserInfoEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(oidcConfigurer -> oidcConfigurer
                        .userInfoEndpoint(userInfoEnpointConfigurer()));
        http
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );
        return http.build();
    }

    @Bean
    SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/images/**", "/css/**", "/js/**", "/favicon.ico").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/health/**", "/metrics/**", "/prometheus/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(configurer -> {
                    configurer
                            .loginPage("/login")
                            .permitAll();
                });

        return http.build();
    }


    @Bean
    public JWKSource<SecurityContext> jwkSource(JwtSignatureProperties jwtSignatureProperties) throws JOSEException {
        RSAKey rsaKey = new RSAKey.Builder(jwtSignatureProperties.publicKey())
                .privateKey(jwtSignatureProperties.privateKey())
                .keyIDFromThumbprint()
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }


    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    private static Customizer<OidcUserInfoEndpointConfigurer> userInfoEnpointConfigurer() {
        return oidcUserInfoEndpointConfigurer ->
                oidcUserInfoEndpointConfigurer.userInfoMapper(
                        oidcUserInfoAuthenticationContext -> {
                            Jwt authentication = (Jwt) ((JwtAuthenticationToken) oidcUserInfoAuthenticationContext.getAuthentication().getPrincipal()).getPrincipal();
                            return new OidcUserInfo(Map.of(
                                    StandardClaimNames.SUB, authentication.getClaimAsString(StandardClaimNames.SUB),
                                    StandardClaimNames.EMAIL, authentication.getClaimAsString(StandardClaimNames.EMAIL),
                                    StandardClaimNames.NAME, authentication.getClaimAsString(StandardClaimNames.NAME),
                                    StandardClaimNames.FAMILY_NAME, authentication.getClaimAsString(StandardClaimNames.FAMILY_NAME),
                                    StandardClaimNames.GIVEN_NAME, authentication.getClaimAsString(StandardClaimNames.GIVEN_NAME),
                                    StandardClaimNames.PREFERRED_USERNAME, authentication.getClaimAsString(StandardClaimNames.PREFERRED_USERNAME),
                                    TokenCustomizerConfiguration.ROLES, authentication.getClaimAsStringList(TokenCustomizerConfiguration.ROLES)
                            ));
                        });
    }

}