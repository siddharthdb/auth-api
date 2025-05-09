// src/main/java/com/enterprise/authapi/repository/RefreshTokenRepository.java
package com.enterprise.authapi.repository;

import com.enterprise.authapi.model.RefreshToken;
import com.enterprise.authapi.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for managing RefreshToken entities
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    /**
     * Find a refresh token by its token value
     *
     * @param token the token value to search for
     * @return an Optional containing the refresh token if found
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * Find all refresh tokens for a user
     *
     * @param user the user whose tokens to retrieve
     * @return a list of refresh tokens
     */
    List<RefreshToken> findByUser(User user);

    /**
     * Delete all expired tokens
     *
     * @param now the current time
     */
    @Modifying
    @Query("DELETE FROM RefreshToken r WHERE r.expiryDate < ?1")
    void deleteAllExpiredTokens(Instant now);

    /**
     * Set all tokens of a user as revoked
     *
     * @param user the user whose tokens to revoke
     */
    @Modifying
    @Query("UPDATE RefreshToken r SET r.revoked = true WHERE r.user = ?1")
    void revokeAllUserTokens(User user);

    /**
     * Delete all refresh tokens for a user
     *
     * @param user the user whose tokens to delete
     * @return the number of tokens deleted
     */
    @Modifying
    int deleteByUser(User user);
}