package com.github.cegiraud.idp4all.service;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.*;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2DeviceAuthorizationResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Optional;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.*;

@Service
public class DeviceCodeFlowService {

    private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";

    private static final String DEVICE_AUTHORIZATION_ENDPOINT = "device_authorization_endpoint";

    private final RestTemplate restTemplate;

    private final OidcUserService userService;

    private final ClientRegistration remote;

    private final JwtDecoderFactory<ClientRegistration> jwtDecoderFactory;


    public DeviceCodeFlowService(ClientRegistrationRepository clientRegistrationRepository) {
        restTemplate = buildRestTemplate();
        remote = clientRegistrationRepository.findByRegistrationId("remote");
        userService = new OidcUserService();
        jwtDecoderFactory = new OidcIdTokenDecoderFactory();
    }

    public OAuth2DeviceAuthorizationResponse createDeviceLoginRequest() {
        Object deviceAuthorizationEndpoint = remote.getProviderDetails().getConfigurationMetadata().get(DEVICE_AUTHORIZATION_ENDPOINT);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(CLIENT_ID, remote.getClientId());
        params.add(SCOPE, String.join(" ", remote.getScopes()));

        RequestEntity<MultiValueMap<String, String>> request = RequestEntity.post(deviceAuthorizationEndpoint.toString())
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(params);

        ResponseEntity<OAuth2DeviceAuthorizationResponse> response = restTemplate.exchange(request, OAuth2DeviceAuthorizationResponse.class);
        return response.getBody();
    }

    public Optional<OAuth2AccessTokenResponse> pollForToken(String deviceCode) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(CLIENT_ID, remote.getClientId());
        params.add(GRANT_TYPE, AuthorizationGrantType.DEVICE_CODE.getValue());
        params.add(DEVICE_CODE, deviceCode);

        try {
            RequestEntity<MultiValueMap<String, String>> request = RequestEntity.post(remote.getProviderDetails().getTokenUri())
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .body(params);
            ResponseEntity<OAuth2AccessTokenResponse> response = restTemplate.exchange(request, OAuth2AccessTokenResponse.class);
            return Optional.ofNullable(response.getBody());
        } catch (RestClientException e) {
            return Optional.empty();
        }

    }

    public Authentication authenticate(OAuth2AccessTokenResponse accessTokenResponse) {
        OidcIdToken idToken = createOidcToken(remote, accessTokenResponse);
        OidcUser oidcUser = this.userService.loadUser(new OidcUserRequest(remote,
                accessTokenResponse.getAccessToken(), idToken));

        return new OAuth2AuthenticationToken(oidcUser, oidcUser.getAuthorities(), remote.getRegistrationId());
    }

    private OidcIdToken createOidcToken(ClientRegistration clientRegistration, OAuth2AccessTokenResponse accessTokenResponse) {
        try {
            JwtDecoder jwtDecoder = jwtDecoderFactory.createDecoder(clientRegistration);
            String idTokenString = accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN).toString();
            Jwt idToken = jwtDecoder.decode(idTokenString);
            return new OidcIdToken(idToken.getTokenValue(), idToken.getIssuedAt(), idToken.getExpiresAt(), idToken.getClaims());
        } catch (JwtException ex) {
            throw new OAuth2AuthenticationException(new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE), ex);
        }
    }

    private static RestTemplate buildRestTemplate() {
        return new RestTemplateBuilder()
                .messageConverters(listHttpMessageConverters())
                .build();
    }

    private static List<HttpMessageConverter<?>> listHttpMessageConverters() {
        OAuth2DeviceAuthorizationResponseHttpMessageConverter oAuth2DeviceAuthorizationResponseHttpMessageConverter = new OAuth2DeviceAuthorizationResponseHttpMessageConverter();
        oAuth2DeviceAuthorizationResponseHttpMessageConverter.setSupportedMediaTypes(List.of(MediaType.APPLICATION_JSON));
        return List.of(
                oAuth2DeviceAuthorizationResponseHttpMessageConverter,
                new OAuth2AccessTokenResponseHttpMessageConverter(),
                new FormHttpMessageConverter());
    }


}
