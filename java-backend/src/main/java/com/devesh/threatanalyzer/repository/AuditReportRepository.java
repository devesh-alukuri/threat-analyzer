package com.devesh.threatanalyzer.repository;

import com.devesh.threatanalyzer.model.AuditReport;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AuditReportRepository extends JpaRepository<AuditReport, Long> {
    List<AuditReport> findAllByOrderByGeneratedAtDesc();
}
