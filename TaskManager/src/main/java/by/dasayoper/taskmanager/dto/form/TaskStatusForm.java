package by.dasayoper.taskmanager.dto.form;

import by.dasayoper.taskmanager.validation.annotations.ValidStatus;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

/**
 * DTO объект для передачи статуса задачи, который используется для обновления статуса задачи.
 * <p>
 * Включает в себя следующее поле:
 * <ul>
 *     <li>Статус задачи {@link #status}, который должен быть валидным (удовлетворять аннотации {@link ValidStatus}) и не может быть null.</li>
 * </ul>
 * </p>
 */
@Data
@Builder
@Schema(description = "Форма для обновления статуса задачи")
public class TaskStatusForm {
    @NotNull
    @ValidStatus(message = "Недопустимый статус задачи")
    @Schema(description = "Статус задачи", example = "ASSIGNED")
    private String status;

    @JsonCreator
    public static TaskStatusForm create(@JsonProperty("status") String status) {
        return TaskStatusForm.builder()
                .status(status)
                .build();
    }
}

