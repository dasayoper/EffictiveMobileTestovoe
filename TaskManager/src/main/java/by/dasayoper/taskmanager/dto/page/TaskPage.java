package by.dasayoper.taskmanager.dto.page;

import by.dasayoper.taskmanager.dto.TaskDto;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.util.List;

/**
 * DTO объект, представляющий страницу с задачами, который используется при применении фильтрации.
 * Используется для передачи данных о странице задач и включает в себя список задач и информацию о пагинации.
 * <p>
 * Содержит следующие поля:
 * <ul>
 *     <li>Список задач {@link #tasks}, представленных в виде списка объектов {@link TaskDto}.</li>
 *     <li>Общее количество страниц {@link #totalPages}, доступных для отображения.</li>
 *     <li>Общее количество элементов {@link #totalElements}, доступных для отображения.</li>
 *     <li>Текущая страница {@link #currentPage}, которая отображается в данный момент.</li>
 * </ul>
 * </p>
 */
@Data
@AllArgsConstructor
@RequiredArgsConstructor
@Builder
@Schema(description = "Страница с задачами с поддержкой пагинации")
public class TaskPage {
    @Schema(description = "Список задач")
    private List<TaskDto> tasks;

    @Schema(description = "Общее количество страниц")
    private Integer totalPages;

    @Schema(description = "Общее количество элементов")
    private Long totalElements;

    @Schema(description = "Текущая страница")
    private Integer currentPage;
}
