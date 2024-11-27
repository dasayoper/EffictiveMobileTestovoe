package by.dasayoper.taskmanager.dto;

import by.dasayoper.taskmanager.model.Comment;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Schema(description = "DTO объект комментария")
public class CommentDto {
    @Schema(description = "ID комментария", example = "<UUID>")
    private UUID id;

    @Schema(description = "Текст комментария", example = "Отличная работа!")
    private String text;

    @Schema(description = "ID автора комментария", example = "<UUID>")
    private UUID authorId;

    @Schema(description = "ID задачи, к которой относится комментарий", example = "<UUID>")
    private UUID taskId;

    @Schema(description = "Дата и время публикации комментария", example = "2024-11-25T15:30:00")
    private LocalDateTime postedAt;

    @Schema(description = "Дата и время последнего редактирования комментария", example = "2024-11-25T16:00:00")
    private LocalDateTime lastEditedAt;

    public static CommentDto from(Comment comment) {
        return CommentDto.builder()
                .id(comment.getId())
                .text(comment.getText())
                .authorId(comment.getAuthor().getId())
                .taskId(comment.getTask().getId())
                .postedAt(comment.getPostedAt())
                .lastEditedAt(comment.getLastEditedAt())
                .build();
    }

    public static List<CommentDto> from(List<Comment> comments) {
        return comments.stream().map(CommentDto::from).collect(Collectors.toList());
    }
}
