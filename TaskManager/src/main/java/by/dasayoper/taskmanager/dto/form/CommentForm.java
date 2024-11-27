package by.dasayoper.taskmanager.dto.form;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

/**
 * DTO объект для комментария, который используется когда пользователь хочет создать или редактировать комментарий.
 * <p>
 * Включает в себя следующее поле:
 * <ul>
 *     <li>Текст комментария {@link #text} (обязательное поле, длина от 1 до 500 символов).</li>
 * </ul>
 * </p>
 */
@Data
@Builder
@Schema(description = "Форма для создания и обновления комментария")
public class CommentForm {

    @NotNull(message = "Комментарий не может быть пустым")
    @Size(min = 1, max = 500, message = "Длина комментария должна быть от 1 до 500 символов")
    @Schema(description = "Текст комментария", example = "Отличная работа!")
    private String text;

    @JsonCreator
    public static CommentForm create(@JsonProperty("text") String text) {
        return CommentForm.builder()
                .text(text)
                .build();
    }
}
