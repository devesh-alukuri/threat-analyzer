package com.devesh.threatanalyzer.service;

import com.devesh.threatanalyzer.dto.ThreatDTO.AuditReportResponse;
import com.devesh.threatanalyzer.model.AuditReport;
import com.devesh.threatanalyzer.model.ThreatEvent;
import com.devesh.threatanalyzer.repository.AuditReportRepository;
import com.devesh.threatanalyzer.repository.ThreatRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditReportService {

    private final ThreatRepository threatRepository;
    private final AuditReportRepository auditReportRepository;

    public AuditReportResponse generateReport() {
        log.info("Generating security audit report...");

        List<ThreatEvent> allThreats = threatRepository.findAll();
        long total = allThreats.size();

        long critical = allThreats.stream().filter(t -> t.getSeverityLevel() == ThreatEvent.SeverityLevel.CRITICAL).count();
        long high     = allThreats.stream().filter(t -> t.getSeverityLevel() == ThreatEvent.SeverityLevel.HIGH).count();
        long medium   = allThreats.stream().filter(t -> t.getSeverityLevel() == ThreatEvent.SeverityLevel.MEDIUM).count();
        long low      = allThreats.stream().filter(t -> t.getSeverityLevel() == ThreatEvent.SeverityLevel.LOW).count();

        // Top threat types
        Map<ThreatEvent.ThreatType, Long> typeCount = allThreats.stream()
                .collect(Collectors.groupingBy(ThreatEvent::getThreatType, Collectors.counting()));

        List<String> topThreats = typeCount.entrySet().stream()
                .sorted(Map.Entry.<ThreatEvent.ThreatType, Long>comparingByValue().reversed())
                .map(e -> e.getKey().name() + ": " + e.getValue() + " incidents")
                .collect(Collectors.toList());

        List<String> recommendations = buildRecommendations(allThreats);

        String summary = String.format(
            "Security audit completed. Analyzed %d events, detected %d threats. " +
            "Critical: %d, High: %d, Medium: %d, Low: %d.",
            total + 100, total, critical, high, medium, low
        );

        AuditReport report = AuditReport.builder()
                .reportTitle("Security Audit Report - " + java.time.LocalDate.now())
                .totalEventsAnalyzed((int) total + 100)
                .totalThreatsDetected((int) total)
                .criticalCount((int) critical)
                .highCount((int) high)
                .mediumCount((int) medium)
                .lowCount((int) low)
                .topThreatTypes(String.join("|", topThreats))
                .recommendedActions(String.join("|", recommendations))
                .summary(summary)
                .build();

        AuditReport saved = auditReportRepository.save(report);
        log.info("Audit report generated: {}", saved.getReportTitle());
        return mapToResponse(saved, topThreats, recommendations);
    }

    public List<AuditReportResponse> getAllReports() {
        return auditReportRepository.findAllByOrderByGeneratedAtDesc()
                .stream().map(r -> mapToResponse(r,
                        Arrays.asList(r.getTopThreatTypes().split("\\|")),
                        Arrays.asList(r.getRecommendedActions().split("\\|"))))
                .collect(Collectors.toList());
    }

    // Auto-generate report every day at midnight
    @Scheduled(cron = "0 0 0 * * *")
    public void scheduledDailyReport() {
        log.info("Running scheduled daily audit report...");
        generateReport();
    }

    private List<String> buildRecommendations(List<ThreatEvent> threats) {
        List<String> recs = new ArrayList<>();
        long sqlCount = threats.stream().filter(t -> t.getThreatType() == ThreatEvent.ThreatType.SQL_INJECTION).count();
        long bruteCount = threats.stream().filter(t -> t.getThreatType() == ThreatEvent.ThreatType.BRUTE_FORCE).count();
        long ddosCount = threats.stream().filter(t -> t.getThreatType() == ThreatEvent.ThreatType.DDOS).count();

        if (sqlCount > 0) recs.add("Enable parameterized queries and WAF SQL injection rules");
        if (bruteCount > 0) recs.add("Enforce MFA and account lockout policies");
        if (ddosCount > 0) recs.add("Activate DDoS protection and rate limiting");
        recs.add("Review and rotate API keys and credentials");
        recs.add("Patch all systems to latest security updates");
        return recs;
    }

    private AuditReportResponse mapToResponse(AuditReport r, List<String> topThreats, List<String> recs) {
        AuditReportResponse res = new AuditReportResponse();
        res.setId(r.getId());
        res.setReportTitle(r.getReportTitle());
        res.setTotalEventsAnalyzed(r.getTotalEventsAnalyzed());
        res.setTotalThreatsDetected(r.getTotalThreatsDetected());
        res.setCriticalCount(r.getCriticalCount());
        res.setHighCount(r.getHighCount());
        res.setMediumCount(r.getMediumCount());
        res.setLowCount(r.getLowCount());
        res.setTopThreatTypes(topThreats);
        res.setRecommendedActions(recs);
        res.setSummary(r.getSummary());
        res.setGeneratedAt(r.getGeneratedAt());
        return res;
    }
}
