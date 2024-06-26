package org.stepup.cinesquareapis.report.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.stepup.cinesquareapis.report.entity.MovieCommentSummary;

@Data
@Schema(description = "사용자가 좋아요한 코멘트 목록 응담 DTO")
public class LikeCommentsResponse {
    @Schema(description = "코멘트 남긴 사용자 고유 키", example = "1")
    private int userId;

    @Schema(description = "코멘트 고유 키", example = "1")
    private int commentId;

    @Schema(description = "회원 별칭", example = "콜라곰")
    private String nickname;

    @Schema(description = "영화 고유 키", example = "1")
    private int movieId;

    @Schema(description = "코멘트 내용", example = "영화 너무 재밌어요!!")
    private String content;

    @Schema(description = "코멘트 좋아요 개수", example = "55")
    private int like;

    @Schema(description = "코멘트 답변 개수", example = "11")
    private int replyCount;

    @Schema(description = "코멘트 사용자가 남긴 별점", example = "4")
    private Float score;

    public LikeCommentsResponse(MovieCommentSummary comment) {
        userId = comment.getUserId();
        nickname = comment.getNickname();
        movieId = comment.getMovieId();
        commentId = comment.getCommentId();
        content = comment.getContent();
        like = comment.getLike();
        replyCount = comment.getReplyCount();
        score = comment.getScore();
    }
}
