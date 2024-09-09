package com.github.cegiraud.idp4all.web;

import com.github.cegiraud.idp4all.service.DeviceCodeFlowService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2DeviceAuthorizationResponse;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.io.IOException;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Optional;

import static org.springframework.http.HttpHeaders.LOCATION;


@Controller
public class LoginController {


    private static final String DEVICE_AUTHORIZATION_RESPONSE = "DEVICE_RESPONSE";

    private final DeviceCodeFlowService deviceCodeFlowService;

    private final SecurityContextRepository securityContextRepository;


    public LoginController(DeviceCodeFlowService deviceCodeFlowService, SecurityContextRepository securityContextRepository) {
        this.deviceCodeFlowService = deviceCodeFlowService;
        this.securityContextRepository = securityContextRepository;
    }


    @GetMapping("/login")
    public String index() {
        return "login";
    }

    @PostMapping(value = "/login")
    public ResponseEntity<OAuth2UserCode> check(HttpSession session, HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException, URISyntaxException {

        OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse = (OAuth2DeviceAuthorizationResponse) session.getAttribute(DEVICE_AUTHORIZATION_RESPONSE);

        if (noDeviceAuthorizationDeviceOrExpired(deviceAuthorizationResponse)) {
            deviceAuthorizationResponse = deviceCodeFlowService.createDeviceLoginRequest();
            session.setAttribute(DEVICE_AUTHORIZATION_RESPONSE, deviceAuthorizationResponse);
            return ResponseEntity.ok(deviceAuthorizationResponse.getUserCode());
        }

        Optional<OAuth2AccessTokenResponse> oAuth2AccessTokenResponse = deviceCodeFlowService.pollForToken(deviceAuthorizationResponse.getDeviceCode().getTokenValue());
        if (oAuth2AccessTokenResponse.isEmpty()) {
            return ResponseEntity.ok(deviceAuthorizationResponse.getUserCode());
        }
        session.removeAttribute(DEVICE_AUTHORIZATION_RESPONSE);
        authenticate(oAuth2AccessTokenResponse.get(), request, response);
        return null;
    }

    public void authenticate(OAuth2AccessTokenResponse accessTokenResponse, HttpServletRequest request, HttpServletResponse response) {
        Authentication authenticationResult = deviceCodeFlowService.authenticate(accessTokenResponse);
        SecurityContext context = SecurityContextHolder.getContext();
        context.setAuthentication(authenticationResult);
        securityContextRepository.saveContext(context, request, response);

        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setRedirectStrategy((httpRequest, httpResponse, url) -> {
            httpResponse.setStatus(HttpStatus.NO_CONTENT.value());
            httpResponse.setHeader(LOCATION, url);
        });
        try {
            successHandler.onAuthenticationSuccess(request, response, authenticationResult);
        } catch (ServletException | IOException e) {
            throw new OAuth2AuthenticationException(new OAuth2Error(e.getMessage()), e);
        }
    }


    private static boolean noDeviceAuthorizationDeviceOrExpired(OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse) {
        return deviceAuthorizationResponse == null || deviceAuthorizationResponse.getDeviceCode() == null || deviceAuthorizationResponse.getDeviceCode().getExpiresAt() == null || Instant.now().isAfter(deviceAuthorizationResponse.getDeviceCode().getExpiresAt());
    }
}
