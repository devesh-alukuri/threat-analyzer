package com.devesh.threatanalyzer.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "threat_events")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String threatId;

    @Column(nullable = false)
    private String sourceIp;

    private String destinationIp;

    private Integer sourcePort;

    private Integer destinationPort;

    private String protocol;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ThreatType threatType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SeverityLevel severityLevel;

    @Column(nullable = false)
    private Double severityScore;

    @Column(nullable = false)
    private Double confidence;

    @Column(columnDefinition = "TEXT")
    private String rawPayload;

    @Column(columnDefinition = "TEXT")
    private String remediationSteps;

    @Enumerated(EnumType.STRING)
    private ThreatStatus status;

    @CreationTimestamp
    private LocalDateTime detectedAt;

    public enum ThreatType {
        NORMAL, PORT_SCAN, BRUTE_FORCE, DDOS, SQL_INJECTION, XSS, MALWARE_TRAFFIC, UNAUTHORIZED_ACCESS
    }

    public enum SeverityLevel {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    public enum ThreatStatus {
        OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    }
}
