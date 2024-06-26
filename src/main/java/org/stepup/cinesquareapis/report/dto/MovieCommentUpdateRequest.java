package org.stepup.cinesquareapis.report.dto;

import lombok.Data;
import org.stepup.cinesquareapis.report.entity.MovieComment;

@Data
public class MovieCommentUpdateRequest {
    private String content;

    public MovieComment toEntity(int commentId, int movieId, Integer userId) {
        return new MovieComment().builder()
                .commentId(commentId)
                .content(content)
                .userId(userId)
                .movieId(movieId)
                .build();
    }
}
