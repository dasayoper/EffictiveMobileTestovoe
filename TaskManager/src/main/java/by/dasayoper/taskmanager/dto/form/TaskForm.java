package by.dasayoper.taskmanager.dto.form;

import by.dasayoper.taskmanager.validation.annotations.ValidPriority;
import by.dasayoper.taskmanager.validation.annotations.ValidStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;
import org.hibernate.validator.constraints.UUID;

/**
 * DTO объект, который используется при создании и редактировании задач.
 * Содержит поля, которые необходимы для создания или обновления задачи в системе.
 * <p>
 * Включает следующие поля:
 * <ul>
 *     <li>Заголовок задачи {@link #title}, который должен быть строкой длиной от 1 до 50 символов. Не может быть пустым.</li>
 *     <li>Описание задачи {@link #description}, которое может быть пустым и иметь максимальную длину 2000 символов.</li>
 *     <li>Статус задачи {@link #status}, который должен быть валидным значением (удовлетворять аннотации {@link ValidStatus}).</li>
 *     <li>Приоритет задачи {@link #priority}, который также должен быть валидным значением (удовлетворять аннотации {@link ValidPriority}).</li>
 *     <li>Идентификатор исполнителя {@link #executorId}, который представляет собой UUID исполнителя задачи.</li>
 * </ul>
 * </p>
 */
@Data
@Builder
@Schema(description = "Форма для создания и обновления задачи")
public class TaskForm {

    @NotNull(message = "Заголовок задачи не может быть пустым")
    @Size(min = 1, max = 50, message = "Длина заголовка должна быть от 1 до 50 символов")
    @Schema(description = "Заголовок задачи", example = "Задача 1")
    private String title;

    @Size(max = 2000, message = "Длина описания задачи не должна превышать 2000 символов")
    @Schema(description = "Описание задачи", example = "Описание задачи для задачи 1")
    private String description;

    @ValidStatus(message = "Недопустимый статус задачи")
    @Schema(description = "Статус задачи", example = "ASSIGNED")
    private String status;

    @ValidPriority(message = "Недопустимый приоритет задачи")
    @Schema(description = "Приоритет задачи", example = "MEDIUM")
    private String priority;

    @UUID(message = "ID исполнителя должен быть указан в формате UUID")
    @Schema(description = "ID исполнителя задачи", example = "<UUID>")
    private String executorId;
}
