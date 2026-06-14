package com.devesh.threatanalyzer.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class ThreatDTO {

    @Data
    public static class AnalyzeRequest {
        @NotBlank(message = "Source IP is required")
        private String sourceIp;

        private String destinationIp;
        private Integer sourcePort;
        private Integer destinationPort;
        private String protocol;
        private String rawPayload;
        private Map<String, Object> networkFeatures;
    }

    @Data
    public static class ThreatResponse {
        private Long id;
        private String threatId;
        private String sourceIp;
        private String destinationIp;
        private Integer sourcePort;
        private Integer destinationPort;
        private String protocol;
        private String threatType;
        private String severityLevel;
        private Double severityScore;
        private Double confidence;
        private List<String> remediationSteps;
        private String status;
        private LocalDateTime detectedAt;
    }

    @Data
    public static class ThreatStatsResponse {
        private Long totalThreats;
        private Long criticalCount;
        private Long highCount;
        private Long mediumCount;
        private Long lowCount;
        private Map<String, Long> threatsByType;
        private Map<String, Long> threatsByStatus;
    }

    @Data
    public static class AuditReportResponse {
        private Long id;
        private String reportTitle;
        private Integer totalEventsAnalyzed;
        private Integer totalThreatsDetected;
        private Integer criticalCount;
        private Integer highCount;
        private Integer mediumCount;
        private Integer lowCount;
        private List<String> topThreatTypes;
        private List<String> recommendedActions;
        private String summary;
        private LocalDateTime generatedAt;
    }

    @Data
    public static class UpdateStatusRequest {
        @NotNull(message = "Status is required")
        private String status;
    }
}
