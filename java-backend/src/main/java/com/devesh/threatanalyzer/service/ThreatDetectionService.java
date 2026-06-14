package com.devesh.threatanalyzer.service;

import com.devesh.threatanalyzer.dto.ThreatDTO.*;
import com.devesh.threatanalyzer.model.ThreatEvent;
import com.devesh.threatanalyzer.repository.ThreatRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ThreatDetectionService {

    private final ThreatRepository threatRepository;

    // Known malicious port ranges
    private static final Set<Integer> SUSPICIOUS_PORTS = Set.of(22, 23, 3389, 445, 135, 139, 1433, 3306, 5432);
    private static final int BRUTE_FORCE_THRESHOLD = 10;
    private static final int PORT_SCAN_THRESHOLD = 20;

    public ThreatResponse analyzeTraffic(AnalyzeRequest request) {
        log.info("Analyzing traffic from IP: {}", request.getSourceIp());

        // Step 1: Detect threat type using rule-based + ML-style scoring
        ThreatEvent.ThreatType threatType = classifyThreat(request);
        double severityScore = calculateSeverityScore(threatType, request);
        ThreatEvent.SeverityLevel severityLevel = determineSeverityLevel(severityScore);
        double confidence = calculateConfidence(threatType, request);
        List<String> remediationSteps = generateRemediationSteps(threatType, request.getSourceIp());

        String threatId = "THR-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

        ThreatEvent event = ThreatEvent.builder()
                .threatId(threatId)
                .sourceIp(request.getSourceIp())
                .destinationIp(request.getDestinationIp())
                .sourcePort(request.getSourcePort())
                .destinationPort(request.getDestinationPort())
                .protocol(request.getProtocol())
                .threatType(threatType)
                .severityLevel(severityLevel)
                .severityScore(severityScore)
                .confidence(confidence)
                .rawPayload(request.getRawPayload())
                .remediationSteps(String.join("|", remediationSteps))
                .status(threatType == ThreatEvent.ThreatType.NORMAL
                        ? ThreatEvent.ThreatStatus.RESOLVED
                        : ThreatEvent.ThreatStatus.OPEN)
                .build();

        ThreatEvent saved = threatRepository.save(event);
        log.info("Threat detected: {} - {} [Score: {}]", threatId, threatType, severityScore);

        return mapToResponse(saved, remediationSteps);
    }

    private ThreatEvent.ThreatType classifyThreat(AnalyzeRequest request) {
        String payload = request.getRawPayload() != null ? request.getRawPayload().toLowerCase() : "";

        // SQL Injection patterns
        if (payload.contains("select ") || payload.contains("union ") ||
            payload.contains("drop table") || payload.contains("' or '1'='1")) {
            return ThreatEvent.ThreatType.SQL_INJECTION;
        }

        // XSS patterns
        if (payload.contains("<script>") || payload.contains("javascript:") ||
            payload.contains("onerror=") || payload.contains("alert(")) {
            return ThreatEvent.ThreatType.XSS;
        }

        // Malware traffic patterns
        if (payload.contains("cmd.exe") || payload.contains("/bin/bash") ||
            payload.contains("powershell") || payload.contains("wget http")) {
            return ThreatEvent.ThreatType.MALWARE_TRAFFIC;
        }

        // Port scan detection — suspicious destination ports
        if (request.getDestinationPort() != null &&
            SUSPICIOUS_PORTS.contains(request.getDestinationPort())) {
            return ThreatEvent.ThreatType.PORT_SCAN;
        }

        // Brute force — repeated auth attempts on port 22 or 3389
        if (request.getDestinationPort() != null &&
           (request.getDestinationPort() == 22 || request.getDestinationPort() == 3389)) {
            long recentAttempts = threatRepository.findBySourceIp(request.getSourceIp())
                    .stream()
                    .filter(t -> t.getThreatType() == ThreatEvent.ThreatType.BRUTE_FORCE ||
                                 t.getThreatType() == ThreatEvent.ThreatType.PORT_SCAN)
                    .count();
            if (recentAttempts >= BRUTE_FORCE_THRESHOLD) {
                return ThreatEvent.ThreatType.BRUTE_FORCE;
            }
        }

        // DDoS — high volume from same IP
        long ipCount = threatRepository.findBySourceIp(request.getSourceIp()).size();
        if (ipCount >= PORT_SCAN_THRESHOLD) {
            return ThreatEvent.ThreatType.DDOS;
        }

        return ThreatEvent.ThreatType.NORMAL;
    }

    private double calculateSeverityScore(ThreatEvent.ThreatType type, AnalyzeRequest req) {
        return switch (type) {
            case CRITICAL, MALWARE_TRAFFIC -> 9.0 + (Math.random() * 1.0);
            case SQL_INJECTION, BRUTE_FORCE -> 7.5 + (Math.random() * 1.5);
            case DDOS, UNAUTHORIZED_ACCESS -> 6.5 + (Math.random() * 1.5);
            case PORT_SCAN, XSS -> 4.0 + (Math.random() * 2.0);
            default -> 1.0 + (Math.random() * 2.0);
        };
    }

    private ThreatEvent.SeverityLevel determineSeverityLevel(double score) {
        if (score >= 9.0) return ThreatEvent.SeverityLevel.CRITICAL;
        if (score >= 7.0) return ThreatEvent.SeverityLevel.HIGH;
        if (score >= 4.0) return ThreatEvent.SeverityLevel.MEDIUM;
        return ThreatEvent.SeverityLevel.LOW;
    }

    private double calculateConfidence(ThreatEvent.ThreatType type, AnalyzeRequest req) {
        // Higher confidence for pattern-matched threats
        return switch (type) {
            case SQL_INJECTION, XSS, MALWARE_TRAFFIC -> 0.92 + (Math.random() * 0.07);
            case BRUTE_FORCE, DDOS -> 0.85 + (Math.random() * 0.10);
            case PORT_SCAN -> 0.78 + (Math.random() * 0.12);
            default -> 0.95 + (Math.random() * 0.05);
        };
    }

    private List<String> generateRemediationSteps(ThreatEvent.ThreatType type, String sourceIp) {
        return switch (type) {
            case SQL_INJECTION -> List.of(
                "Immediately block IP " + sourceIp + " at WAF",
                "Enable parameterized queries in all database calls",
                "Review and sanitize all user inputs",
                "Audit database access logs for data exfiltration",
                "Update WAF rules to block SQL injection patterns"
            );
            case XSS -> List.of(
                "Block source IP " + sourceIp + " at firewall",
                "Enable Content Security Policy (CSP) headers",
                "Sanitize all HTML output using encoding libraries",
                "Review all user input rendering in the frontend",
                "Update WAF XSS filter rules"
            );
            case BRUTE_FORCE -> List.of(
                "Block IP " + sourceIp + " immediately",
                "Enable account lockout after 5 failed attempts",
                "Enforce multi-factor authentication (MFA)",
                "Review authentication logs for compromised accounts",
                "Consider geo-blocking suspicious regions"
            );
            case DDOS -> List.of(
                "Enable rate limiting on all API endpoints",
                "Activate DDoS protection via AWS Shield or Cloudflare",
                "Block IP range of " + sourceIp,
                "Scale up infrastructure to absorb traffic",
                "Contact ISP to filter upstream traffic"
            );
            case PORT_SCAN -> List.of(
                "Block source IP " + sourceIp + " at firewall",
                "Enable port scan detection rules in IDS/IPS",
                "Review open ports and close unnecessary ones",
                "Enable network segmentation",
                "Monitor for follow-up exploitation attempts"
            );
            case MALWARE_TRAFFIC -> List.of(
                "Isolate affected system immediately",
                "Block IP " + sourceIp + " at perimeter firewall",
                "Run full antivirus/EDR scan on affected hosts",
                "Preserve system images for forensic analysis",
                "Notify incident response team"
            );
            default -> List.of("No immediate action required", "Continue monitoring");
        };
    }

    public List<ThreatResponse> getAllThreats(String severity, String type) {
        List<ThreatEvent> threats;
        if (severity != null) {
            threats = threatRepository.findBySeverityLevel(
                    ThreatEvent.SeverityLevel.valueOf(severity.toUpperCase()));
        } else if (type != null) {
            threats = threatRepository.findByThreatType(
                    ThreatEvent.ThreatType.valueOf(type.toUpperCase()));
        } else {
            threats = threatRepository.findAll();
        }
        return threats.stream().map(t -> mapToResponse(t, parseRemediation(t.getRemediationSteps())))
                .collect(Collectors.toList());
    }

    public ThreatResponse getThreatById(String threatId) {
        ThreatEvent event = threatRepository.findByThreatId(threatId)
                .orElseThrow(() -> new RuntimeException("Threat not found: " + threatId));
        return mapToResponse(event, parseRemediation(event.getRemediationSteps()));
    }

    public ThreatStatsResponse getStats() {
        ThreatStatsResponse stats = new ThreatStatsResponse();
        stats.setTotalThreats(threatRepository.count());
        stats.setCriticalCount(threatRepository.countBySeverityLevel(ThreatEvent.SeverityLevel.CRITICAL));
        stats.setHighCount(threatRepository.countBySeverityLevel(ThreatEvent.SeverityLevel.HIGH));
        stats.setMediumCount(threatRepository.countBySeverityLevel(ThreatEvent.SeverityLevel.MEDIUM));
        stats.setLowCount(threatRepository.countBySeverityLevel(ThreatEvent.SeverityLevel.LOW));

        Map<String, Long> byType = new LinkedHashMap<>();
        threatRepository.countGroupedByThreatType()
                .forEach(row -> byType.put(row[0].toString(), (Long) row[1]));
        stats.setThreatsByType(byType);

        Map<String, Long> byStatus = new LinkedHashMap<>();
        for (ThreatEvent.ThreatStatus s : ThreatEvent.ThreatStatus.values()) {
            byStatus.put(s.name(), threatRepository.countByStatus(s));
        }
        stats.setThreatsByStatus(byStatus);

        return stats;
    }

    public ThreatResponse updateThreatStatus(String threatId, String status) {
        ThreatEvent event = threatRepository.findByThreatId(threatId)
                .orElseThrow(() -> new RuntimeException("Threat not found: " + threatId));
        event.setStatus(ThreatEvent.ThreatStatus.valueOf(status.toUpperCase()));
        threatRepository.save(event);
        return mapToResponse(event, parseRemediation(event.getRemediationSteps()));
    }

    private ThreatResponse mapToResponse(ThreatEvent e, List<String> remediation) {
        ThreatResponse res = new ThreatResponse();
        res.setId(e.getId());
        res.setThreatId(e.getThreatId());
        res.setSourceIp(e.getSourceIp());
        res.setDestinationIp(e.getDestinationIp());
        res.setSourcePort(e.getSourcePort());
        res.setDestinationPort(e.getDestinationPort());
        res.setProtocol(e.getProtocol());
        res.setThreatType(e.getThreatType().name());
        res.setSeverityLevel(e.getSeverityLevel().name());
        res.setSeverityScore(Math.round(e.getSeverityScore() * 10.0) / 10.0);
        res.setConfidence(Math.round(e.getConfidence() * 100.0) / 100.0);
        res.setRemediationSteps(remediation);
        res.setStatus(e.getStatus().name());
        res.setDetectedAt(e.getDetectedAt());
        return res;
    }

    private List<String> parseRemediation(String raw) {
        if (raw == null || raw.isBlank()) return List.of();
        return Arrays.asList(raw.split("\\|"));
    }
}
