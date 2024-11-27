package by.dasayoper.taskmanager.dto;

import by.dasayoper.taskmanager.model.Task;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Schema(description = "DTO объект задачи")
public class TaskDto {
    @Schema(description = "ID задачи", example = "<UUID>")
    private UUID id;

    @Schema(description = "Заголовок задачи", example = "Задача 1")
    private String title;

    @Schema(description = "Описание задачи", example = "Описание задачи для задачи 1")
    private String description;

    @Schema(description = "Статус задачи", example = "ASSIGNED")
    private String status;

    @Schema(description = "Приоритет задачи", example = "MEDIUM")
    private String priority;

    @Schema(description = "ID автора задачи", example = "<UUID>")
    private UUID authorId;

    @Schema(description = "ID исполнителя задачи", example = "<UUID>")
    private UUID executorId;

    @Schema(description = "Список комментариев к задаче")
    private List<CommentDto> comments;

    public static TaskDto from(Task task) {
        return TaskDto.builder()
                .id(task.getId())
                .title(task.getTitle())
                .description(task.getDescription())
                .status(task.getStatus().name())
                .priority(task.getPriority().name())
                .authorId(task.getAuthor().getId())
                .executorId(task.getExecutor() != null ? task.getExecutor().getId() : null)
                .comments(CommentDto.from(task.getComments().stream().toList()))
                .build();
    }

    public static List<TaskDto> from(List<Task> tasks) {
        return tasks.stream().map(TaskDto::from).collect(Collectors.toList());
    }
}
