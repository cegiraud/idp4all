package com.github.cegiraud.idp4all;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
@ConfigurationPropertiesScan
public class IdP4AllApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdP4AllApplication.class, args);
    }

}
