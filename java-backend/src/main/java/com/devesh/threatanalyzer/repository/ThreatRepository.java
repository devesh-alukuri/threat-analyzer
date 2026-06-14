package com.devesh.threatanalyzer.repository;

import com.devesh.threatanalyzer.model.ThreatEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Repository
public interface ThreatRepository extends JpaRepository<ThreatEvent, Long> {
    Optional<ThreatEvent> findByThreatId(String threatId);
    List<ThreatEvent> findByThreatType(ThreatEvent.ThreatType threatType);
    List<ThreatEvent> findBySeverityLevel(ThreatEvent.SeverityLevel severityLevel);
    List<ThreatEvent> findByStatus(ThreatEvent.ThreatStatus status);
    List<ThreatEvent> findBySourceIp(String sourceIp);
    List<ThreatEvent> findByDetectedAtBetween(LocalDateTime from, LocalDateTime to);

    long countBySeverityLevel(ThreatEvent.SeverityLevel severityLevel);
    long countByThreatType(ThreatEvent.ThreatType threatType);
    long countByStatus(ThreatEvent.ThreatStatus status);

    @Query("SELECT t.threatType, COUNT(t) FROM ThreatEvent t GROUP BY t.threatType ORDER BY COUNT(t) DESC")
    List<Object[]> countGroupedByThreatType();
}
