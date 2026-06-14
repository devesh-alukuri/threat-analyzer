package com.devesh.threatanalyzer.controller;

import com.devesh.threatanalyzer.dto.ThreatDTO.*;
import com.devesh.threatanalyzer.service.AuditReportService;
import com.devesh.threatanalyzer.service.ThreatDetectionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/threats")
@RequiredArgsConstructor
@Tag(name = "Threat Analyzer API", description = "Real-time cybersecurity threat detection and audit reporting")
public class ThreatController {

    private final ThreatDetectionService threatDetectionService;
    private final AuditReportService auditReportService;

    @PostMapping("/analyze")
    @Operation(summary = "Submit network traffic data for threat analysis")
    public ResponseEntity<ThreatResponse> analyzeTraffic(@Valid @RequestBody AnalyzeRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(threatDetectionService.analyzeTraffic(request));
    }

    @GetMapping
    @Operation(summary = "Get all detected threats with optional filters")
    public ResponseEntity<List<ThreatResponse>> getAllThreats(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String type) {
        return ResponseEntity.ok(threatDetectionService.getAllThreats(severity, type));
    }

    @GetMapping("/{threatId}")
    @Operation(summary = "Get threat detail by threat ID")
    public ResponseEntity<ThreatResponse> getThreat(@PathVariable String threatId) {
        return ResponseEntity.ok(threatDetectionService.getThreatById(threatId));
    }

    @GetMapping("/stats")
    @Operation(summary = "Get threat statistics summary")
    public ResponseEntity<ThreatStatsResponse> getStats() {
        return ResponseEntity.ok(threatDetectionService.getStats());
    }

    @PutMapping("/{threatId}/status")
    @Operation(summary = "Update threat investigation status")
    public ResponseEntity<ThreatResponse> updateStatus(
            @PathVariable String threatId,
            @RequestBody UpdateStatusRequest request) {
        return ResponseEntity.ok(threatDetectionService.updateThreatStatus(threatId, request.getStatus()));
    }

    @PostMapping("/report")
    @Operation(summary = "Generate a full security audit report")
    public ResponseEntity<AuditReportResponse> generateReport() {
        return ResponseEntity.status(HttpStatus.CREATED).body(auditReportService.generateReport());
    }

    @GetMapping("/report")
    @Operation(summary = "Get all previously generated audit reports")
    public ResponseEntity<List<AuditReportResponse>> getAllReports() {
        return ResponseEntity.ok(auditReportService.getAllReports());
    }
}
