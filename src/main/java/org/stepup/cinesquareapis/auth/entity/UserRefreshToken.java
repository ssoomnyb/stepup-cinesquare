package org.stepup.cinesquareapis.auth.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.stepup.cinesquareapis.user.entity.User;

import java.time.LocalDateTime;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Setter
@Entity
@Table(name = "tb_user_refresh_token")
public class UserRefreshToken {
    // 연관된 회원ID를 외래키 겸 기본키로 지정
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer userId;

    // 한 명당 1개의 리프레시 토큰만 가질 수 있게 할 것이므로 RefreshToken과 User를 1:1 연관관계로 묶어줌
    @OneToOne(fetch = FetchType.LAZY)
    @MapsId
    @JoinColumn(name = "user_id")
    private User user;

    private String refreshToken;

    private LocalDateTime refreshTokenExpiryDate;

    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime created;

    @UpdateTimestamp
    private LocalDateTime updated;

    public UserRefreshToken(User user, String refreshToken, int time) {
        this.user = user;
        this.refreshToken = refreshToken;
        this.created = LocalDateTime.now();
        this.updated = LocalDateTime.now();
        this.refreshTokenExpiryDate = calculateExpiryDate(time);
    }

    public void updateRefreshToken(String refreshToken, int time) {
        this.refreshToken = refreshToken;
        this.refreshTokenExpiryDate = calculateExpiryDate(time);
    }

    public boolean validateRefreshToken(String refreshToken) {
        return this.refreshToken.equals(refreshToken) && !isExpired();
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.refreshTokenExpiryDate);
    }

    private LocalDateTime calculateExpiryDate(int time) {
        return LocalDateTime.now().plusMinutes(time); // 분 단위로 만료 시간 계산
    }
}
