package com.devesh.threatanalyzer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class ThreatAnalyzerApplication {
    public static void main(String[] args) {
        SpringApplication.run(ThreatAnalyzerApplication.class, args);
    }
}
