package com.github.cegiraud.idp4all.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties("jwt-signature")
public record JwtSignatureProperties(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
}