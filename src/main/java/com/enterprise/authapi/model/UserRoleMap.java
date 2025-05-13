package com.enterprise.authapi.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Entity representing the mapping between Users and Roles
 * This provides an indirect relationship with additional metadata
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "USER_ROLE_MAP")
public class UserRoleMap {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "USER_ID", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "ROLE_ID", nullable = false)
    private Role role;

    @Column(name = "ASSIGNED_BY")
    private String assignedBy;

    @Column(name = "ASSIGNED_DATE", nullable = false)
    private LocalDateTime assignedDate;

    @Column(name = "EXPIRY_DATE")
    private LocalDateTime expiryDate;

    @Column(name = "IS_ACTIVE", nullable = false)
    private boolean active = true;

    @PrePersist
    protected void onCreate() {
        if (assignedDate == null) {
            assignedDate = LocalDateTime.now();
        }
    }
}