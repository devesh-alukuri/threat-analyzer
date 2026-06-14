package com.devesh.threatanalyzer.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_reports")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String reportTitle;

    @Column(nullable = false)
    private Integer totalEventsAnalyzed;

    @Column(nullable = false)
    private Integer totalThreatsDetected;

    private Integer criticalCount;
    private Integer highCount;
    private Integer mediumCount;
    private Integer lowCount;

    @Column(columnDefinition = "TEXT")
    private String topThreatTypes;

    @Column(columnDefinition = "TEXT")
    private String recommendedActions;

    @Column(columnDefinition = "TEXT")
    private String summary;

    @CreationTimestamp
    private LocalDateTime generatedAt;
}
